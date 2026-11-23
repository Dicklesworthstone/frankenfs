//! FsOps integration using the parent's native-layout/faultable-storage fixtures.
//! These fixtures exercise the storage model, not native OpenZFS or FUSE mounts.

use super::*;
use ffs_core::vfs::{FileType, ReleaseRequest, RequestOp};
use ffs_core::{FsOps, InodeAttr, RequestScope, SetAttrRequest};
use ffs_types::InodeNumber;
use ffs_zfs::ZfsFs;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, UNIX_EPOCH};

const ROOT: InodeNumber = InodeNumber(1);

fn writer_fixture(
    cx: &Cx,
    spec: &PoolFixtureSpec,
) -> (ZfsTransactionEngine, Vec<FaultableMemberDevice>) {
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
    (engine, devices)
}

fn lookup(fs: &ZfsFs, cx: &Cx, parent: InodeNumber, name: &str) -> InodeAttr {
    fs.lookup(cx, &mut RequestScope::empty(), parent, OsStr::new(name))
        .unwrap()
}

fn create(fs: &ZfsFs, cx: &Cx, parent: InodeNumber, name: &str) -> InodeAttr {
    fs.create(
        cx,
        &mut RequestScope::empty(),
        parent,
        OsStr::new(name),
        0o640,
        1234,
        5678,
    )
    .unwrap()
}

fn read(fs: &ZfsFs, cx: &Cx, ino: InodeNumber) -> Vec<u8> {
    fs.read(cx, &mut RequestScope::empty(), ino, 0, 65_536)
        .unwrap()
}

fn release(fs: &ZfsFs, cx: &Cx, ino: InodeNumber, fh: u64) {
    fs.release(
        cx,
        &mut RequestScope::empty(),
        ReleaseRequest {
            ino,
            fh,
            flags: libc::O_RDWR,
            lock_owner: None,
            flush: false,
        },
    )
    .unwrap();
}

fn io_counts(devices: &[FaultableMemberDevice]) -> Vec<(usize, usize)> {
    devices
        .iter()
        .map(|device| {
            let media = device.state.lock().unwrap();
            (media.write_calls, media.sync_calls)
        })
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn rename_exchange_fsops_keeps_handles_and_moves_nonempty_directories() {
    let cx = Cx::for_testing();
    for zpl_version in [4, 5] {
        let (engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                ..PoolFixtureSpec::default()
            },
        );
        let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
        let mut scope = RequestScope::empty();
        let first = lookup(&fs, &cx, ROOT, "hello.txt");
        let second = lookup(&fs, &cx, ROOT, "keep.bin");
        let first_bytes = read(&fs, &cx, first.ino);
        let second_bytes = read(&fs, &cx, second.ino);
        let (first_handle, _) = fs.open(&cx, &mut scope, first.ino, libc::O_RDWR).unwrap();
        let (second_handle, _) = fs
            .open(&cx, &mut scope, second.ino, libc::O_RDONLY)
            .unwrap();
        fs.rename2(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("hello.txt"),
            ROOT,
            OsStr::new("keep.bin"),
            libc::RENAME_EXCHANGE,
        )
        .unwrap();
        assert_eq!(lookup(&fs, &cx, ROOT, "hello.txt").ino, second.ino);
        assert_eq!(lookup(&fs, &cx, ROOT, "keep.bin").ino, first.ino);
        assert_eq!(read(&fs, &cx, first.ino), first_bytes);
        assert_eq!(read(&fs, &cx, second.ino), second_bytes);
        fs.write(&cx, &mut scope, first.ino, 0, b"open handle")
            .unwrap();
        assert!(read(&fs, &cx, lookup(&fs, &cx, ROOT, "keep.bin").ino).starts_with(b"open handle"));
        fs.fsync(&cx, &mut scope, first.ino, first_handle, false)
            .unwrap();
        fs.fsync(&cx, &mut scope, second.ino, second_handle, false)
            .unwrap();
        release(&fs, &cx, first.ino, first_handle);
        release(&fs, &cx, second.ino, second_handle);

        fs.link(&cx, &mut scope, first.ino, ROOT, OsStr::new("alias"))
            .unwrap();
        // Exchanging two hard links (or the same name) is a namespace no-op.
        let alias_io = io_counts(&devices);
        for destination in ["keep.bin", "alias"] {
            fs.rename2(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("alias"),
                ROOT,
                OsStr::new(destination),
                libc::RENAME_EXCHANGE,
            )
            .unwrap();
            assert_eq!(lookup(&fs, &cx, ROOT, "alias").ino, first.ino);
            assert_eq!(lookup(&fs, &cx, ROOT, "keep.bin").ino, first.ino);
            assert_eq!(fs.getattr(&cx, &mut scope, first.ino).unwrap().nlink, 2);
            assert_eq!(io_counts(&devices), alias_io);
        }
        let symlink = fs
            .symlink(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("shortcut"),
                Path::new("keep.bin"),
                0,
                0,
            )
            .unwrap();
        fs.rename2(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("alias"),
            ROOT,
            OsStr::new("shortcut"),
            libc::RENAME_EXCHANGE,
        )
        .unwrap();
        assert_eq!(lookup(&fs, &cx, ROOT, "alias").ino, symlink.ino);
        assert_eq!(lookup(&fs, &cx, ROOT, "shortcut").ino, first.ino);
        assert_eq!(
            fs.readlink(&cx, &mut scope, symlink.ino).unwrap(),
            b"keep.bin"
        );
        assert_eq!(fs.getattr(&cx, &mut scope, first.ino).unwrap().nlink, 2);

        let left = fs
            .mkdir(&cx, &mut scope, ROOT, OsStr::new("left"), 0o755, 0, 0)
            .unwrap();
        let right = fs
            .mkdir(&cx, &mut scope, ROOT, OsStr::new("right"), 0o755, 0, 0)
            .unwrap();
        let inner = fs
            .mkdir(&cx, &mut scope, left.ino, OsStr::new("inner"), 0o755, 0, 0)
            .unwrap();
        let left_child = create(&fs, &cx, inner.ino, "left-child");
        let right_child = create(&fs, &cx, right.ino, "right-child");
        let root_links = fs.getattr(&cx, &mut scope, ROOT).unwrap().nlink;
        let left_links = fs.getattr(&cx, &mut scope, left.ino).unwrap().nlink;
        // A nonempty directory can exchange with a regular file in another parent.
        fs.rename2(
            &cx,
            &mut scope,
            left.ino,
            OsStr::new("inner"),
            right.ino,
            OsStr::new("right-child"),
            libc::RENAME_EXCHANGE,
        )
        .unwrap();
        assert_eq!(lookup(&fs, &cx, left.ino, "inner").ino, right_child.ino);
        assert_eq!(lookup(&fs, &cx, right.ino, "right-child").ino, inner.ino);
        assert_eq!(
            lookup(&fs, &cx, inner.ino, "left-child").ino,
            left_child.ino
        );
        assert_eq!(lookup(&fs, &cx, inner.ino, "..").ino, right.ino);
        assert_eq!(fs.getattr(&cx, &mut scope, ROOT).unwrap().nlink, root_links);
        assert_eq!(
            fs.getattr(&cx, &mut scope, left.ino).unwrap().nlink,
            left_links - 1
        );
        assert_eq!(fs.getattr(&cx, &mut scope, right.ino).unwrap().nlink, 3);
        // Both directories are nonempty. A same-parent exchange preserves nlinks.
        fs.rename2(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("left"),
            ROOT,
            OsStr::new("right"),
            libc::RENAME_EXCHANGE,
        )
        .unwrap();
        assert_eq!(lookup(&fs, &cx, ROOT, "left").ino, right.ino);
        assert_eq!(lookup(&fs, &cx, ROOT, "right").ino, left.ino);
        assert_eq!(fs.getattr(&cx, &mut scope, ROOT).unwrap().nlink, root_links);

        let before = io_counts(&devices);
        for flags in [
            libc::RENAME_EXCHANGE | libc::RENAME_NOREPLACE,
            libc::RENAME_EXCHANGE | libc::RENAME_WHITEOUT,
        ] {
            assert_eq!(
                fs.rename2(
                    &cx,
                    &mut scope,
                    ROOT,
                    OsStr::new("left"),
                    ROOT,
                    OsStr::new("right"),
                    flags
                )
                .unwrap_err()
                .to_errno(),
                libc::EINVAL
            );
        }
        assert_eq!(
            fs.rename2(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("left"),
                ROOT,
                OsStr::new("absent"),
                libc::RENAME_EXCHANGE
            )
            .unwrap_err()
            .to_errno(),
            libc::ENOENT
        );
        assert_eq!(io_counts(&devices), before);
        assert_eq!(lookup(&fs, &cx, ROOT, "left").ino, right.ino);
        assert_eq!(lookup(&fs, &cx, ROOT, "right").ino, left.ino);
    }
}

#[test]
fn native_fsops_lifecycle_persists_metadata_and_reads_its_latest_txg() {
    let cx = Cx::for_testing();
    for (zpl_version, mirror_width, ashift) in [(4, 1, 9), (5, 2, 12)] {
        let (engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                mirror_width,
                ashift,
                image_bytes: 24 * 1024 * 1024,
                ..PoolFixtureSpec::default()
            },
        );
        let native_capacity = engine.storage_identity().asize;
        let native_free = engine.free_bytes();
        let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
        let mut scope = RequestScope::empty();
        let stats = fs.statfs(&cx, &mut scope, ROOT).unwrap();
        assert_eq!(stats.fragment_size, 1_u32 << ashift);
        assert_eq!(
            stats.blocks,
            native_capacity / u64::from(stats.fragment_size)
        );
        assert_eq!(
            stats.blocks_free,
            native_free / u64::from(stats.fragment_size)
        );
        let dir = fs
            .mkdir(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("work"),
                0o2750,
                1234,
                5678,
            )
            .unwrap();
        assert_eq!((dir.perm, dir.uid, dir.gid), (0o2750, 1234, 5678));
        let file = fs
            .create(
                &cx,
                &mut scope,
                dir.ino,
                OsStr::new("payload"),
                0o640,
                1234,
                9999,
            )
            .unwrap();
        assert_eq!((file.perm, file.uid, file.gid), (0o640, 1234, 5678));
        let nested = fs
            .mkdir(
                &cx,
                &mut scope,
                dir.ino,
                OsStr::new("inherited"),
                0o750,
                1234,
                9999,
            )
            .unwrap();
        assert_eq!((nested.perm, nested.gid), (0o2750, 5678));
        fs.rmdir(&cx, &mut scope, dir.ino, OsStr::new("inherited"))
            .unwrap();
        let before_killpriv = io_counts(&devices);
        assert!(
            !fs.removexattr(&cx, &mut scope, file.ino, "security.capability")
                .unwrap()
        );
        assert_eq!(io_counts(&devices), before_killpriv);
        assert_eq!(
            fs.write(&cx, &mut scope, file.ino, 3, b"payload").unwrap(),
            7
        );
        assert_eq!(read(&fs, &cx, file.ino), b"\0\0\0payload");
        assert_eq!(lookup(&fs, &cx, dir.ino, "payload").ino, file.ino);
        let linked = fs
            .link(&cx, &mut scope, file.ino, ROOT, OsStr::new("alias"))
            .unwrap();
        assert_eq!((linked.ino, linked.nlink), (file.ino, 2));
        fs.rename(
            &cx,
            &mut scope,
            dir.ino,
            OsStr::new("payload"),
            ROOT,
            OsStr::new("persisted"),
        )
        .unwrap();
        assert_eq!(lookup(&fs, &cx, ROOT, "persisted").ino, file.ino);
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("alias"))
            .unwrap();
        fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("work")).unwrap();
        let resized = fs
            .setattr(
                &cx,
                &mut scope,
                file.ino,
                &SetAttrRequest {
                    size: Some(6),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap();
        assert_eq!((resized.size, resized.nlink), (6, 1));
        assert_eq!(read(&fs, &cx, file.ino), b"\0\0\0pay");
        // The preceding lifecycle both allocates and reclaims storage, so its
        // net free-space delta need not be negative. Exercise allocation and
        // reclamation separately; a stale statfs result must fail both checks.
        let probe = create(&fs, &cx, ROOT, "allocation-probe");
        let before_allocation = fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free;
        let payload = vec![0xA5; 1024 * 1024];
        assert_eq!(
            fs.write(&cx, &mut scope, probe.ino, 0, &payload).unwrap(),
            u32::try_from(payload.len()).unwrap()
        );
        let after_allocation = fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free;
        assert!(
            after_allocation < before_allocation,
            "new data must consume native space: {before_allocation} -> {after_allocation}"
        );
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("allocation-probe"))
            .unwrap();
        let reported_free = fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free;
        assert!(
            reported_free > after_allocation,
            "final unlink must release native data: {after_allocation} -> {reported_free}"
        );

        let before_rejected = io_counts(&devices);
        let token = fs.last_durable_token().unwrap().unwrap();
        let error = fs
            .setattr(
                &cx,
                &mut scope,
                file.ino,
                &SetAttrRequest {
                    size: Some(0),
                    mode: Some(0o777),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap_err();
        assert_eq!(error.to_errno(), libc::EOPNOTSUPP);
        assert_eq!(io_counts(&devices), before_rejected);
        assert_eq!(fs.last_durable_token().unwrap().unwrap(), token);
        assert_eq!(read(&fs, &cx, file.ino), b"\0\0\0pay");
        let error = fs
            .setattr(
                &cx,
                &mut scope,
                file.ino,
                &SetAttrRequest {
                    size: Some(0),
                    mtime: Some(resized.mtime),
                    uid: Some(resized.uid + 1),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap_err();
        assert_eq!(error.to_errno(), libc::EOPNOTSUPP);
        assert_eq!(io_counts(&devices), before_rejected);
        assert_eq!(read(&fs, &cx, file.ino), b"\0\0\0pay");
        fs.fsync(&cx, &mut scope, file.ino, 0, false).unwrap();
        fs.fsyncdir(&cx, &mut scope, ROOT, 0, false).unwrap();
        fs.flush_on_destroy(&cx).unwrap();
        drop(fs);

        for device in &devices {
            device.state.lock().unwrap().crash_drop_unsynced();
        }
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &devices,
            POOL_GUID,
            Some(token.published_slot()),
        );
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
        assert_eq!(
            reported_free,
            reopened.free_bytes() / u64::from(stats.fragment_size),
            "mounted statfs must match allocation reconstructed from durable media"
        );
        let fs = ZfsFs::with_writer(&cx, reopened, vec![b"data".to_vec()]).unwrap();
        assert_eq!(
            fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free,
            reported_free
        );
        let persisted = lookup(&fs, &cx, ROOT, "persisted");
        assert_eq!(
            (persisted.perm, persisted.uid, persisted.gid),
            (0o640, 1234, 5678)
        );
        assert_eq!(read(&fs, &cx, persisted.ino), b"\0\0\0pay");
        assert_eq!(persisted.generation, file.generation);
        assert!(
            fs.lookup(&cx, &mut scope, ROOT, OsStr::new("work"))
                .is_err()
        );
    }
}

#[test]
fn native_setattr_persists_exact_times_and_size_together_without_changing_snapshots() {
    let cx = Cx::for_testing();
    let access_time = UNIX_EPOCH - Duration::new(1, 123_456_789);
    let modified_time = UNIX_EPOCH + Duration::new(4_100_000_000, 987_654_321);
    for (zpl_version, mirror_width, ashift, deadlist_mode, with_sa_spill) in [
        (4, 1, 9, DeadlistMode::Bpobj, false),
        (5, 2, 12, DeadlistMode::NativeDeadlist, true),
    ] {
        let (engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                mirror_width,
                ashift,
                deadlist_mode,
                with_sa_spill,
                with_sa_spill_timestamps: zpl_version == 5,
                user_accounting: true,
                image_bytes: 24 * 1024 * 1024,
                ..PoolFixtureSpec::default()
            },
        );
        let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
        let mut scope = RequestScope::empty();
        let original = lookup(&fs, &cx, ROOT, "hello.txt");
        let original_bytes = read(&fs, &cx, original.ino);
        let control = lookup(&fs, &cx, ROOT, ".zfs");
        let snapshots = lookup(&fs, &cx, control.ino, "snapshot");
        let snapshot = lookup(&fs, &cx, snapshots.ino, "before");
        let historical = lookup(&fs, &cx, snapshot.ino, "hello.txt");

        let updated = fs
            .setattr(
                &cx,
                &mut scope,
                original.ino,
                &SetAttrRequest {
                    atime: Some(access_time),
                    mtime: Some(modified_time),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap();
        assert_eq!((updated.atime, updated.mtime), (access_time, modified_time));
        assert!(updated.ctime > original.ctime);
        assert_eq!(
            (
                updated.generation,
                updated.crtime,
                updated.size,
                updated.nlink
            ),
            (
                original.generation,
                original.crtime,
                original.size,
                original.nlink
            )
        );
        assert_eq!(
            (updated.perm, updated.uid, updated.gid),
            (original.perm, original.uid, original.gid)
        );
        assert_eq!(read(&fs, &cx, original.ino), original_bytes);
        assert_eq!(
            fs.last_durable_token().unwrap().unwrap().committed_txg(),
            INITIAL_TXG + 1
        );

        let directory = fs
            .setattr(
                &cx,
                &mut scope,
                ROOT,
                &SetAttrRequest {
                    atime: Some(access_time),
                    mtime: Some(modified_time),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap();
        assert_eq!(
            (directory.atime, directory.mtime),
            (access_time, modified_time)
        );
        assert_eq!(lookup(&fs, &cx, ROOT, "hello.txt").ino, original.ino);

        let previous = fs.last_durable_token().unwrap().unwrap();
        let resized = fs
            .setattr(
                &cx,
                &mut scope,
                original.ino,
                &SetAttrRequest {
                    size: Some(8),
                    atime: Some(access_time),
                    mtime: Some(modified_time),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap();
        assert_eq!(
            (resized.size, resized.atime, resized.mtime),
            (8, access_time, modified_time)
        );
        assert_eq!(read(&fs, &cx, original.ino), original_bytes[..8]);
        assert_eq!(
            fs.last_durable_token().unwrap().unwrap().committed_txg(),
            previous.committed_txg() + 1,
            "one compound request must publish one TXG"
        );

        let grown_size = original.size + 17;
        let grown = fs
            .setattr(
                &cx,
                &mut scope,
                original.ino,
                &SetAttrRequest {
                    size: Some(grown_size),
                    mtime: Some(modified_time),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap();
        let mut expected = original_bytes[..8].to_vec();
        expected.resize(usize::try_from(grown_size).unwrap(), 0);
        assert_eq!(
            (grown.size, grown.atime, grown.mtime),
            (grown_size, access_time, modified_time)
        );
        assert_eq!(read(&fs, &cx, original.ino), expected);
        assert_eq!(read(&fs, &cx, historical.ino), original_bytes);
        let unchanged = fs.getattr(&cx, &mut scope, historical.ino).unwrap();
        assert_eq!(
            (unchanged.atime, unchanged.mtime, unchanged.ctime),
            (historical.atime, historical.mtime, historical.ctime)
        );
        let counts = io_counts(&devices);
        assert_eq!(
            fs.setattr(
                &cx,
                &mut scope,
                historical.ino,
                &SetAttrRequest {
                    mtime: Some(modified_time),
                    ..SetAttrRequest::default()
                }
            )
            .unwrap_err()
            .to_errno(),
            libc::EROFS
        );
        assert_eq!(io_counts(&devices), counts);
        let token = fs.last_durable_token().unwrap().unwrap();
        drop(fs);

        for device in &devices {
            device.state.lock().unwrap().crash_drop_unsynced();
        }
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &devices,
            POOL_GUID,
            Some(token.published_slot()),
        );
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
        let fs = ZfsFs::with_writer(&cx, reopened, vec![b"data".to_vec()]).unwrap();
        let persisted = lookup(&fs, &cx, ROOT, "hello.txt");
        assert_eq!(
            (persisted.size, persisted.atime, persisted.mtime),
            (grown_size, access_time, modified_time)
        );
        assert_eq!(persisted.generation, original.generation);
        assert_eq!(persisted.crtime, original.crtime);
        assert_eq!(read(&fs, &cx, persisted.ino), expected);
        let root = fs.getattr(&cx, &mut scope, ROOT).unwrap();
        assert_eq!((root.atime, root.mtime), (access_time, modified_time));
    }
}

#[test]
fn native_setattr_refuses_unsupported_compound_fields_before_any_mutation() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(
        &cx,
        &PoolFixtureSpec {
            deadlist_mode: DeadlistMode::NativeDeadlist,
            with_sa_spill: true,
            ..PoolFixtureSpec::default()
        },
    );
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    let original = lookup(&fs, &cx, ROOT, "hello.txt");
    let payload = read(&fs, &cx, original.ino);
    let counts = io_counts(&devices);
    for attrs in [
        SetAttrRequest {
            mode: Some(0o777),
            ..SetAttrRequest::default()
        },
        SetAttrRequest {
            uid: Some(original.uid + 1),
            ..SetAttrRequest::default()
        },
        SetAttrRequest {
            gid: Some(original.gid + 1),
            ..SetAttrRequest::default()
        },
    ] {
        let attrs = SetAttrRequest {
            size: Some(0),
            atime: Some(UNIX_EPOCH),
            mtime: Some(UNIX_EPOCH),
            ..attrs
        };
        assert_eq!(
            fs.setattr(&cx, &mut scope, original.ino, &attrs)
                .unwrap_err()
                .to_errno(),
            libc::EOPNOTSUPP
        );
        let after = fs.getattr(&cx, &mut scope, original.ino).unwrap();
        assert_eq!(
            (after.size, after.atime, after.mtime, after.ctime),
            (
                original.size,
                original.atime,
                original.mtime,
                original.ctime
            )
        );
        assert_eq!(read(&fs, &cx, original.ino), payload);
        assert_eq!(io_counts(&devices), counts);
        assert!(fs.last_durable_token().unwrap().is_none());
    }
    assert_eq!(
        fs.setattr(
            &cx,
            &mut scope,
            ROOT,
            &SetAttrRequest {
                size: Some(0),
                mtime: Some(UNIX_EPOCH),
                ..SetAttrRequest::default()
            }
        )
        .unwrap_err()
        .to_errno(),
        libc::EISDIR
    );
    assert_eq!(io_counts(&devices), counts);
    // Exact mode/owner values need no ACL or ownership mutation and can accompany times.
    let accepted = fs
        .setattr(
            &cx,
            &mut scope,
            original.ino,
            &SetAttrRequest {
                mode: Some(original.perm),
                uid: Some(original.uid),
                gid: Some(original.gid),
                mtime: Some(UNIX_EPOCH),
                ..SetAttrRequest::default()
            },
        )
        .unwrap();
    assert_eq!(accepted.mtime, UNIX_EPOCH);
    assert_eq!(read(&fs, &cx, original.ino), payload);
}

#[test]
fn native_setattr_obeys_native_immutable_readonly_and_append_flags() {
    let cx = Cx::for_testing();
    for (flags, mtime_allowed) in [
        (0x0000_0010_0000_0000, false), // ZFS_IMMUTABLE allows atime only.
        (0x0000_0001_0000_0000, true),  // ZFS_READONLY prohibits size changes.
        (0x0000_0040_0000_0000, true),  // ZFS_APPENDONLY prohibits truncation.
    ] {
        let (engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                deadlist_mode: DeadlistMode::NativeDeadlist,
                zpl_flags: BTreeMap::from([(4, flags)]),
                ..PoolFixtureSpec::default()
            },
        );
        let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
        let mut scope = RequestScope::empty();
        let file = lookup(&fs, &cx, ROOT, "hello.txt");
        let payload = read(&fs, &cx, file.ino);
        let atime = UNIX_EPOCH + Duration::new(100, 1);
        let updated = fs
            .setattr(
                &cx,
                &mut scope,
                file.ino,
                &SetAttrRequest {
                    atime: Some(atime),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap();
        assert_eq!((updated.atime, updated.mtime), (atime, file.mtime));
        let token = fs.last_durable_token().unwrap().unwrap();
        let counts = io_counts(&devices);
        assert_eq!(
            fs.setattr(
                &cx,
                &mut scope,
                file.ino,
                &SetAttrRequest {
                    size: Some(0),
                    mtime: Some(UNIX_EPOCH),
                    ..SetAttrRequest::default()
                }
            )
            .unwrap_err()
            .to_errno(),
            libc::EPERM
        );
        assert_eq!(io_counts(&devices), counts);
        assert_eq!(fs.last_durable_token().unwrap().unwrap(), token);
        let outcome = fs.setattr(
            &cx,
            &mut scope,
            file.ino,
            &SetAttrRequest {
                mtime: Some(UNIX_EPOCH),
                ..SetAttrRequest::default()
            },
        );
        if mtime_allowed {
            assert_eq!(outcome.unwrap().mtime, UNIX_EPOCH);
        } else {
            assert_eq!(outcome.unwrap_err().to_errno(), libc::EPERM);
            assert_eq!(io_counts(&devices), counts);
            assert_eq!(fs.last_durable_token().unwrap().unwrap(), token);
        }
        assert_eq!(read(&fs, &cx, file.ino), payload);
    }
}

#[test]
fn native_setattr_rejects_invalid_times_without_truncating_or_publishing() {
    let cx = Cx::for_testing();
    let (mut engine, devices) = writer_fixture(
        &cx,
        &PoolFixtureSpec {
            deadlist_mode: DeadlistMode::NativeDeadlist,
            ..PoolFixtureSpec::default()
        },
    );
    let dataset = [b"data".to_vec()];
    let valid = Timestamp {
        seconds: -1,
        nanos: 500_000_000,
    };
    let invalid = Timestamp {
        seconds: 1,
        nanos: 1_000_000_000,
    };
    let counts = io_counts(&devices);
    for (atime, mtime, ctime) in [
        (Some(invalid), None, valid),
        (None, Some(invalid), valid),
        (Some(valid), Some(valid), invalid),
    ] {
        let result = engine.set_attributes(
            &cx,
            &dataset,
            4,
            &ffs_zfs::ZfsSetAttr {
                size: Some(0),
                atime,
                mtime,
            },
            ctime,
            ZfsDataChecksum::Fletcher4,
        );
        assert!(matches!(result, ZfsTxOutcome::NotCommitted(_)));
        assert_eq!(engine.committed_txg(), INITIAL_TXG);
        assert!(!engine.requires_recovery());
        assert_eq!(io_counts(&devices), counts);
    }
    for attrs in [
        ffs_zfs::ZfsSetAttr::default(),
        ffs_zfs::ZfsSetAttr {
            size: Some(u64::MAX),
            ..ffs_zfs::ZfsSetAttr::default()
        },
    ] {
        let result =
            engine.set_attributes(&cx, &dataset, 4, &attrs, valid, ZfsDataChecksum::Fletcher4);
        assert!(matches!(result, ZfsTxOutcome::NotCommitted(ref error)
            if error.to_errno() == libc::EINVAL));
        assert_eq!(engine.committed_txg(), INITIAL_TXG);
        assert_eq!(io_counts(&devices), counts);
    }
    let mut mos = engine.open_read_objects(&cx).unwrap();
    let mut head = mos.zpl(&cx, &dataset).unwrap();
    assert_eq!(head.read(&cx, 4, 0, 8192).unwrap(), b"SNAPDATA".repeat(512));
    assert_eq!(
        head.stat(&cx, 4).unwrap().0.times,
        [Timestamp {
            seconds: 1_700_000_000,
            nanos: 0
        }; 4]
    );
}

#[test]
fn native_setattr_persistence_cuts_never_split_size_from_explicit_times() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let attrs = ffs_zfs::ZfsSetAttr {
        size: Some(8),
        atime: Some(Timestamp {
            seconds: -2,
            nanos: 876_543_211,
        }),
        mtime: Some(Timestamp {
            seconds: 4_100_000_000,
            nanos: 987_654_321,
        }),
    };
    let ctime = Timestamp {
        seconds: 1_715_000_300,
        nanos: 17,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 2,
        with_sa_spill: true,
        deadlist_mode: DeadlistMode::NativeDeadlist,
        ..PoolFixtureSpec::default()
    });
    let probe_devices: Vec<_> = built
        .members
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
    probe
        .set_attributes(&cx, &dataset, 4, &attrs, ctime, ZfsDataChecksum::Fletcher4)
        .into_result()
        .unwrap();
    let events = probe.persistence_events().to_vec();
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
            let result =
                engine.set_attributes(&cx, &dataset, 4, &attrs, ctime, ZfsDataChecksum::Fletcher4);
            if sequence <= first_publication {
                assert!(
                    matches!(result, ZfsTxOutcome::NotCommitted(_)),
                    "{:?}",
                    cut.stage
                );
            } else if sequence < durable {
                assert!(
                    matches!(result, ZfsTxOutcome::Uncertain { .. }),
                    "{:?}",
                    cut.stage
                );
            } else {
                assert!(result.is_committed(), "{:?}", cut.stage);
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
            let committed = mos.txg == INITIAL_TXG + 1;
            if sequence <= first_publication {
                assert!(!committed);
            }
            if sequence >= durable {
                assert!(committed);
            }
            let mut head = mos.zpl(&cx, &dataset).unwrap();
            let metadata = head.stat(&cx, 4).unwrap().0;
            if committed {
                assert_eq!(metadata.size, 8);
                assert_eq!(
                    metadata.times[..3],
                    [attrs.atime.unwrap(), attrs.mtime.unwrap(), ctime]
                );
                assert_eq!(head.read(&cx, 4, 0, 8192).unwrap(), b"SNAPDATA");
            } else {
                assert_eq!(metadata.size, built.snap_hello_expected.len() as u64);
                assert_eq!(
                    metadata.times,
                    [Timestamp {
                        seconds: 1_700_000_000,
                        nanos: 0
                    }; 4]
                );
                assert_eq!(
                    head.read(&cx, 4, 0, 8192).unwrap(),
                    built.snap_hello_expected
                );
            }
            let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
            assert_eq!(
                snapshot.stat(&cx, 4).unwrap().0.times,
                [Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 0
                }; 4]
            );
            assert_eq!(
                snapshot.read(&cx, 4, 0, 8192).unwrap(),
                built.snap_hello_expected
            );
            assert_pool_scrub_and_allocation_clean(&cx, &devices, built.pool_guid, None);
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_symlink_targets_persist_inline_and_in_data_with_namespace_lifecycle() {
    let cx = Cx::for_testing();
    for (zpl_version, mirror_width, ashift) in [(4, 1, 9), (5, 2, 12)] {
        let (engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                mirror_width,
                ashift,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                with_sa_spill: zpl_version == 5,
                user_accounting: true,
                image_bytes: 24 * 1024 * 1024,
                ..PoolFixtureSpec::default()
            },
        );
        let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
        let mut scope = RequestScope::empty();
        let directory = fs
            .mkdir(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("links"),
                0o2750,
                1234,
                5678,
            )
            .unwrap();
        let targets = [
            b".".to_vec(),
            vec![b'a'; 56],
            vec![b'b'; 57],
            vec![b'c'; 4095],
            vec![b'.', b'/', 0xff, b'/', 0xfe],
        ];
        let mut created = Vec::new();
        for (index, target) in targets.into_iter().enumerate() {
            let name = format!("link-{index}");
            let previous = fs.last_durable_token().unwrap().unwrap();
            let link = fs
                .symlink(
                    &cx,
                    &mut scope,
                    directory.ino,
                    OsStr::new(&name),
                    Path::new(OsStr::from_bytes(&target)),
                    1234,
                    9999,
                )
                .unwrap();
            assert_eq!(link.kind, FileType::Symlink);
            assert_eq!(
                (link.perm, link.uid, link.gid, link.nlink),
                (0o777, 1234, 5678, 1)
            );
            assert_eq!(link.size, u64::try_from(target.len()).unwrap());
            if target.len() <= 56 {
                assert_eq!(link.blocks, 0);
            } else {
                assert!(link.blocks > 0);
            }
            assert_eq!(fs.readlink(&cx, &mut scope, link.ino).unwrap(), target);
            assert_eq!(lookup(&fs, &cx, directory.ino, &name), link);
            assert_eq!(
                fs.last_durable_token().unwrap().unwrap().committed_txg(),
                previous.committed_txg() + 1
            );
            assert!(
                fs.readdir(&cx, &mut scope, directory.ino, 0)
                    .unwrap()
                    .iter()
                    .any(|entry| entry.name == name.as_bytes()
                        && entry.ino == link.ino
                        && entry.kind == FileType::Symlink)
            );
            let counts = io_counts(&devices);
            let token = fs.last_durable_token().unwrap().unwrap();
            assert_eq!(
                fs.symlink(
                    &cx,
                    &mut scope,
                    directory.ino,
                    OsStr::new(&name),
                    Path::new("different-target"),
                    0,
                    0,
                )
                .unwrap_err()
                .to_errno(),
                libc::EEXIST
            );
            assert_eq!(io_counts(&devices), counts);
            assert_eq!(fs.last_durable_token().unwrap().unwrap(), token);
            let retained_name = format!("kept-{index}");
            fs.rename(
                &cx,
                &mut scope,
                directory.ino,
                OsStr::new(&name),
                directory.ino,
                OsStr::new(&retained_name),
            )
            .unwrap();
            let retained = lookup(&fs, &cx, directory.ino, &retained_name);
            assert_eq!(
                (retained.ino, retained.generation),
                (link.ino, link.generation)
            );
            assert_eq!(fs.readlink(&cx, &mut scope, retained.ino).unwrap(), target);
            created.push((retained_name, target, retained));
        }
        let control = lookup(&fs, &cx, ROOT, ".zfs");
        let snapshots = lookup(&fs, &cx, control.ino, "snapshot");
        let before = lookup(&fs, &cx, snapshots.ino, "before");
        assert_eq!(
            fs.lookup(&cx, &mut scope, before.ino, OsStr::new("links"))
                .unwrap_err()
                .to_errno(),
            libc::ENOENT
        );
        let counts = io_counts(&devices);
        assert_eq!(
            fs.symlink(
                &cx,
                &mut scope,
                before.ino,
                OsStr::new("forbidden"),
                Path::new("target"),
                0,
                0,
            )
            .unwrap_err()
            .to_errno(),
            libc::EROFS
        );
        assert_eq!(io_counts(&devices), counts);
        let historical = lookup(&fs, &cx, before.ino, "hello.txt");
        assert_eq!(read(&fs, &cx, historical.ino), b"SNAPDATA".repeat(512));
        let token = fs.last_durable_token().unwrap().unwrap();
        drop(fs);
        for device in &devices {
            device.state.lock().unwrap().crash_drop_unsynced();
        }
        let fresh: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let engine = open_engine_on_devices(
            &cx,
            &fresh,
            default_write_opts(POOL_GUID, token.published_slot()),
        )
        .unwrap();
        let reopened = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
        let directory = lookup(&reopened, &cx, ROOT, "links");
        for (name, target, original) in created {
            let link = lookup(&reopened, &cx, directory.ino, &name);
            assert_eq!(
                (
                    link.kind,
                    link.size,
                    link.generation,
                    link.crtime,
                    link.uid,
                    link.gid
                ),
                (
                    original.kind,
                    original.size,
                    original.generation,
                    original.crtime,
                    1234,
                    5678
                )
            );
            assert_eq!(
                reopened.readlink(&cx, &mut scope, link.ino).unwrap(),
                target
            );
            reopened
                .unlink(&cx, &mut scope, directory.ino, OsStr::new(&name))
                .unwrap();
            assert!(reopened.getattr(&cx, &mut scope, link.ino).is_err());
        }
        reopened
            .rmdir(&cx, &mut scope, ROOT, OsStr::new("links"))
            .unwrap();
        let live = lookup(&reopened, &cx, ROOT, "hello.txt");
        assert_eq!(read(&reopened, &cx, live.ino), b"SNAPDATA".repeat(512));
        let token = reopened.last_durable_token().unwrap().unwrap();
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &fresh,
            POOL_GUID,
            Some(token.published_slot()),
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_symlink_creation_refuses_invalid_targets_and_parent_restrictions_without_writes() {
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_715_000_310,
        nanos: 19,
    };
    let dataset = [b"data".to_vec()];
    let (mut engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
    for (target, time, errno) in [
        (Vec::new(), timestamp, libc::ENOENT),
        (b"has\0nul".to_vec(), timestamp, libc::EINVAL),
        (vec![b'x'; 4096], timestamp, libc::ENAMETOOLONG),
        (
            b"target".to_vec(),
            Timestamp {
                seconds: 1,
                nanos: 1_000_000_000,
            },
            libc::EINVAL,
        ),
    ] {
        assert_native_write_refused(&mut engine, &devices, errno, |writer| {
            writer.create_symlink(
                &cx,
                &dataset,
                2,
                b"refused",
                &target,
                0,
                0,
                time,
                ZfsDataChecksum::Fletcher4,
            )
        });
    }
    let fs = ZfsFs::with_writer(&cx, engine, dataset.to_vec()).unwrap();
    let mut scope = RequestScope::empty();
    let counts = io_counts(&devices);
    for (target, errno) in [
        (Vec::new(), libc::ENOENT),
        (b"has\0nul".to_vec(), libc::EINVAL),
        (vec![b'x'; 4096], libc::ENAMETOOLONG),
    ] {
        assert_eq!(
            fs.symlink(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("refused"),
                Path::new(OsStr::from_bytes(&target)),
                0,
                0,
            )
            .unwrap_err()
            .to_errno(),
            errno
        );
        assert_eq!(io_counts(&devices), counts);
        assert!(fs.last_durable_token().unwrap().is_none());
    }
    assert_eq!(
        fs.lookup(&cx, &mut scope, ROOT, OsStr::new("refused"))
            .unwrap_err()
            .to_errno(),
        libc::ENOENT
    );

    for (spec, errno) in [
        (
            PoolFixtureSpec {
                zpl_flags: BTreeMap::from([(2, 0x0000_0010_0000_0000)]),
                ..PoolFixtureSpec::default()
            },
            libc::EPERM,
        ),
        (
            PoolFixtureSpec {
                zpl_flags: BTreeMap::from([(2, 0x0000_4000_0000_0000)]),
                ..PoolFixtureSpec::default()
            },
            libc::EOPNOTSUPP,
        ),
        (
            PoolFixtureSpec {
                root_properties: vec![(b"readonly", 1)],
                ..PoolFixtureSpec::default()
            },
            libc::EROFS,
        ),
    ] {
        let (mut engine, devices) = writer_fixture(&cx, &spec);
        assert_native_write_refused(&mut engine, &devices, errno, |writer| {
            writer.create_symlink(
                &cx,
                &dataset,
                2,
                b"refused",
                b"target",
                0,
                0,
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
        });
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_symlink_persistence_cuts_publish_complete_target_or_no_link() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let target = vec![b'x'; 4095];
    let timestamp = Timestamp {
        seconds: 1_715_000_320,
        nanos: 23,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 2,
        with_sa_spill: true,
        deadlist_mode: DeadlistMode::NativeDeadlist,
        user_accounting: true,
        ..PoolFixtureSpec::default()
    });
    let probe_devices: Vec<_> = built
        .members
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
    probe
        .create_symlink(
            &cx,
            &dataset,
            2,
            b"atomic-link",
            &target,
            1234,
            5678,
            timestamp,
            ZfsDataChecksum::Sha256,
        )
        .into_result()
        .unwrap();
    let events = probe.persistence_events().to_vec();
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
            let result = engine.create_symlink(
                &cx,
                &dataset,
                2,
                b"atomic-link",
                &target,
                1234,
                5678,
                timestamp,
                ZfsDataChecksum::Sha256,
            );
            if sequence <= first_publication {
                assert!(
                    matches!(result, ZfsTxOutcome::NotCommitted(_)),
                    "{:?}",
                    cut.stage
                );
            } else if sequence < durable {
                assert!(
                    matches!(result, ZfsTxOutcome::Uncertain { .. }),
                    "{:?}",
                    cut.stage
                );
            } else {
                assert!(result.is_committed(), "{:?}", cut.stage);
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
            let committed = mos.txg == INITIAL_TXG + 1;
            if sequence <= first_publication {
                assert!(!committed);
            }
            if sequence >= durable {
                assert!(committed);
            }
            let mut head = mos.zpl(&cx, &dataset).unwrap();
            if committed {
                let object = head.resolve(&cx, b"/atomic-link").unwrap();
                let metadata = head.stat(&cx, object).unwrap().0;
                assert_eq!(metadata.kind, ffs_ondisk::zfs_zpl::Kind::Symlink);
                assert_eq!(
                    (metadata.mode, metadata.links, metadata.size),
                    (0o120_777, 1, 4095)
                );
                assert_eq!((metadata.uid, metadata.gid), (1234, 5678));
                assert_eq!(metadata.times, [timestamp; 4]);
                assert_eq!(head.readlink(&cx, object).unwrap(), target);
            } else {
                assert_eq!(
                    head.resolve(&cx, b"/atomic-link").unwrap_err().to_errno(),
                    libc::ENOENT
                );
            }
            let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
            assert_eq!(
                snapshot
                    .resolve(&cx, b"/atomic-link")
                    .unwrap_err()
                    .to_errno(),
                libc::ENOENT
            );
            assert_eq!(
                snapshot.read(&cx, 4, 0, 8192).unwrap(),
                built.snap_hello_expected
            );
            assert_pool_scrub_and_allocation_clean(&cx, &devices, built.pool_guid, None);
        }
    }
}

#[test]
fn reused_native_objects_get_new_inodes_and_old_directory_cookies_fail_closed() {
    let cx = Cx::for_testing();
    let (engine, _devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    let old = create(&fs, &cx, ROOT, "old");
    fs.write(&cx, &mut scope, old.ino, 0, b"old private content")
        .unwrap();
    let page = fs.readdir(&cx, &mut scope, ROOT, 0).unwrap();
    let cookie = page.last().unwrap().offset;
    assert!(i64::try_from(cookie).is_ok());
    fs.unlink(&cx, &mut scope, ROOT, OsStr::new("old")).unwrap();
    let new = create(&fs, &cx, ROOT, "new");
    assert_ne!(new.ino, old.ino);
    assert_ne!(new.generation, old.generation);
    fs.write(&cx, &mut scope, new.ino, 0, b"new independent content")
        .unwrap();
    assert_eq!(read(&fs, &cx, new.ino), b"new independent content");
    assert_eq!(
        fs.read(&cx, &mut scope, old.ino, 0, 1024)
            .unwrap_err()
            .to_errno(),
        libc::ESTALE
    );
    assert_eq!(
        fs.write(&cx, &mut scope, old.ino, 0, b"wrong object")
            .unwrap_err()
            .to_errno(),
        libc::ESTALE
    );
    assert_eq!(
        fs.readdir(&cx, &mut scope, ROOT, cookie)
            .unwrap_err()
            .to_errno(),
        libc::ESTALE
    );
    assert!(
        fs.readdir(&cx, &mut scope, ROOT, 0)
            .unwrap()
            .iter()
            .any(|entry| entry.name == b"new")
    );
}

#[test]
fn directory_moves_refresh_cached_parents_and_no_replace_is_atomic() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    let left = fs
        .mkdir(&cx, &mut scope, ROOT, OsStr::new("left"), 0o755, 0, 0)
        .unwrap();
    let right = fs
        .mkdir(&cx, &mut scope, ROOT, OsStr::new("right"), 0o755, 0, 0)
        .unwrap();
    let nested = fs
        .mkdir(&cx, &mut scope, left.ino, OsStr::new("nested"), 0o700, 0, 0)
        .unwrap();
    let child = create(&fs, &cx, nested.ino, "child");
    fs.write(&cx, &mut scope, child.ino, 0, b"inside moved directory")
        .unwrap();
    assert_eq!(lookup(&fs, &cx, nested.ino, "..").ino, left.ino);
    fs.rename(
        &cx,
        &mut scope,
        left.ino,
        OsStr::new("nested"),
        right.ino,
        OsStr::new("nested"),
    )
    .unwrap();
    assert_eq!(lookup(&fs, &cx, right.ino, "nested").ino, nested.ino);
    assert_eq!(lookup(&fs, &cx, nested.ino, "..").ino, right.ino);
    assert_eq!(
        read(&fs, &cx, lookup(&fs, &cx, nested.ino, "child").ino),
        b"inside moved directory"
    );
    let other = create(&fs, &cx, ROOT, "other");
    let target = create(&fs, &cx, ROOT, "target");
    let before = io_counts(&devices);
    assert_eq!(
        fs.rename2(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("other"),
            ROOT,
            OsStr::new("target"),
            libc::RENAME_NOREPLACE
        )
        .unwrap_err()
        .to_errno(),
        libc::EEXIST
    );
    assert_eq!(io_counts(&devices), before);
    assert_eq!(lookup(&fs, &cx, ROOT, "other").ino, other.ino);
    assert_eq!(lookup(&fs, &cx, ROOT, "target").ino, target.ino);
}

#[test]
fn create_and_open_handles_retain_replaced_files_until_the_last_release() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    assert!(fs.requires_stateful_open());
    let (file, created_handle, _) = fs
        .create_open(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("open"),
            0o640,
            1234,
            5678,
            libc::O_CREAT | libc::O_RDWR,
        )
        .unwrap();
    assert_ne!(created_handle, 0);
    fs.write(&cx, &mut scope, file.ino, 0, b"still open")
        .unwrap();
    let (handle, _) = fs.open(&cx, &mut scope, file.ino, libc::O_RDWR).unwrap();
    assert_ne!(handle, 0);
    assert_ne!(handle, created_handle);
    release(&fs, &cx, file.ino, created_handle);
    fs.link(&cx, &mut scope, file.ino, ROOT, OsStr::new("another-link"))
        .unwrap();
    fs.unlink(&cx, &mut scope, ROOT, OsStr::new("another-link"))
        .unwrap();
    let replacement = create(&fs, &cx, ROOT, "replacement");
    fs.write(&cx, &mut scope, replacement.ino, 0, b"replacement bytes")
        .unwrap();
    fs.rename(
        &cx,
        &mut scope,
        ROOT,
        OsStr::new("replacement"),
        ROOT,
        OsStr::new("open"),
    )
    .unwrap();
    assert_eq!(lookup(&fs, &cx, ROOT, "open").ino, replacement.ino);
    assert_eq!(fs.getattr(&cx, &mut scope, file.ino).unwrap().nlink, 0);
    assert_eq!(read(&fs, &cx, file.ino), b"still open");
    fs.write(&cx, &mut scope, file.ino, 0, b"after move")
        .unwrap();
    assert_eq!(read(&fs, &cx, file.ino), b"after move");
    assert_eq!(read(&fs, &cx, replacement.ino), b"replacement bytes");
    release(&fs, &cx, file.ino, handle);

    // FUSE's legacy oracle counts cached LOOKUP references. A closed file must
    // remain removable even while its old inode is present in the kernel cache.
    fs.install_open_handle_oracle(Arc::new(|_| 1));
    assert_eq!(lookup(&fs, &cx, ROOT, "open").ino, replacement.ino);
    assert!(fs.getattr(&cx, &mut scope, file.ino).is_err());
    assert_eq!(
        fs.flush(&cx, &mut scope, file.ino, handle, 0)
            .unwrap_err()
            .to_errno(),
        libc::EBADF
    );
    assert_eq!(
        fs.release(
            &cx,
            &mut scope,
            ReleaseRequest {
                ino: file.ino,
                fh: handle,
                flags: libc::O_RDWR,
                lock_owner: None,
                flush: false,
            }
        )
        .unwrap_err()
        .to_errno(),
        libc::EBADF
    );
    fs.unlink(&cx, &mut scope, ROOT, OsStr::new("open"))
        .unwrap();
    assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
}

#[test]
fn symlink_replacement_retains_open_regular_data_and_refuses_orphan_relink() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    let old = create(&fs, &cx, ROOT, "destination");
    fs.write(&cx, &mut scope, old.ino, 0, b"old payload")
        .unwrap();
    let (handle, _) = fs.open(&cx, &mut scope, old.ino, libc::O_RDWR).unwrap();
    let link = fs
        .symlink(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("source-link"),
            Path::new("target/location"),
            1234,
            5678,
        )
        .unwrap();

    fs.rename(
        &cx,
        &mut scope,
        ROOT,
        OsStr::new("source-link"),
        ROOT,
        OsStr::new("destination"),
    )
    .unwrap();
    let replacement = lookup(&fs, &cx, ROOT, "destination");
    assert_eq!(replacement.ino, link.ino);
    assert_eq!(replacement.kind, FileType::Symlink);
    assert_eq!(
        fs.readlink(&cx, &mut scope, replacement.ino).unwrap(),
        b"target/location"
    );
    assert!(matches!(
        fs.lookup(&cx, &mut scope, ROOT, OsStr::new("source-link")),
        Err(FfsError::NotFound(_))
    ));
    assert_eq!(fs.getattr(&cx, &mut scope, old.ino).unwrap().nlink, 0);
    assert_eq!(read(&fs, &cx, old.ino), b"old payload");
    fs.write(&cx, &mut scope, old.ino, 0, b"new payload")
        .unwrap();
    assert_eq!(read(&fs, &cx, old.ino), b"new payload");

    // A queued zero-link object cannot be resurrected while its orphan record
    // still authorizes reclamation on final release.
    let counts = io_counts(&devices);
    let token = fs.last_durable_token().unwrap().unwrap();
    assert_eq!(
        fs.link(&cx, &mut scope, old.ino, ROOT, OsStr::new("resurrected"))
            .unwrap_err()
            .to_errno(),
        libc::ENOENT
    );
    assert_eq!(io_counts(&devices), counts);
    assert_eq!(fs.last_durable_token().unwrap().unwrap(), token);
    assert!(matches!(
        fs.lookup(&cx, &mut scope, ROOT, OsStr::new("resurrected")),
        Err(FfsError::NotFound(_))
    ));

    release(&fs, &cx, old.ino, handle);
    assert!(fs.getattr(&cx, &mut scope, old.ino).is_err());
    assert_eq!(lookup(&fs, &cx, ROOT, "destination").ino, link.ino);
    assert_eq!(
        fs.readlink(&cx, &mut scope, link.ino).unwrap(),
        b"target/location"
    );
    assert!(
        !fs.finalize_unlinked_inode(&cx, &mut scope, old.ino)
            .unwrap()
    );
    fs.unlink(&cx, &mut scope, ROOT, OsStr::new("destination"))
        .unwrap();
    assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
}

#[test]
fn unlinked_open_files_survive_name_reuse_and_restart_reclaims_only_the_orphan() {
    let cx = Cx::for_testing();
    let dataset = vec![b"data".to_vec()];
    for zpl_version in [4, 5] {
        let (engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                mirror_width: 2,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                user_accounting: true,
                image_bytes: 24 * 1024 * 1024,
                ..PoolFixtureSpec::default()
            },
        );
        let fs = ZfsFs::with_writer(&cx, engine, dataset.clone()).unwrap();
        let mut scope = RequestScope::empty();
        let old = lookup(&fs, &cx, ROOT, "hello.txt");
        let original = read(&fs, &cx, old.ino);
        let (first, _) = fs.open(&cx, &mut scope, old.ino, libc::O_RDWR).unwrap();
        let (second, _) = fs.open(&cx, &mut scope, old.ino, libc::O_RDWR).unwrap();
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("hello.txt"))
            .unwrap();
        assert!(matches!(
            fs.lookup(&cx, &mut scope, ROOT, OsStr::new("hello.txt")),
            Err(FfsError::NotFound(_))
        ));
        assert_eq!(fs.getattr(&cx, &mut scope, old.ino).unwrap().nlink, 0);
        assert_eq!(read(&fs, &cx, old.ino), original);
        release(&fs, &cx, old.ino, first);
        let replacement = create(&fs, &cx, ROOT, "hello.txt");
        assert_ne!(old.ino, replacement.ino);
        fs.write(&cx, &mut scope, replacement.ino, 0, b"new name")
            .unwrap();
        let orphan_mtime = UNIX_EPOCH + Duration::new(1_715_000_333, 987_654_321);
        let truncated = fs
            .setattr(
                &cx,
                &mut scope,
                old.ino,
                &SetAttrRequest {
                    size: Some(0),
                    mtime: Some(orphan_mtime),
                    ..SetAttrRequest::default()
                },
            )
            .unwrap();
        assert_eq!((truncated.size, truncated.nlink), (0, 0));
        assert_eq!(truncated.mtime, orphan_mtime);
        assert_eq!(truncated.generation, old.generation);
        fs.write(&cx, &mut scope, old.ino, 0, b"unlinked but still open")
            .unwrap();
        assert_eq!(read(&fs, &cx, old.ino), b"unlinked but still open");
        assert_eq!(read(&fs, &cx, replacement.ino), b"new name");
        fs.fsync(&cx, &mut scope, old.ino, second, false).unwrap();
        let token = fs.last_durable_token().unwrap().unwrap();
        drop(fs); // Process death: no final RELEASE, only the durable native queue survives.
        for device in &devices {
            device.state.lock().unwrap().crash_drop_unsynced();
        }
        let fresh: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let engine = open_engine_on_devices(
            &cx,
            &fresh,
            default_write_opts(POOL_GUID, token.published_slot()),
        )
        .unwrap();
        let pending = engine.pending_unlinks(&cx, &dataset).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].generation, old.generation);
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let mut head = mos.zpl(&cx, &dataset).unwrap();
        assert_eq!(
            head.read(&cx, pending[0].object, 0, 4096).unwrap(),
            b"unlinked but still open"
        );
        let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
        assert_eq!(
            snapshot.read(&cx, pending[0].object, 0, 8192).unwrap(),
            original
        );

        let recovered = ZfsFs::with_writer(&cx, engine, dataset.clone()).unwrap();
        assert_eq!(
            read(
                &recovered,
                &cx,
                lookup(&recovered, &cx, ROOT, "hello.txt").ino
            ),
            b"new name"
        );
        let recovered_token = recovered.last_durable_token().unwrap().unwrap();
        assert!(recovered_token.committed_txg() > token.committed_txg());
        drop(recovered);
        let engine = open_engine_on_devices(
            &cx,
            &fresh,
            default_write_opts(POOL_GUID, recovered_token.published_slot()),
        )
        .unwrap();
        assert_eq!(
            engine.pending_unlinks(&cx, &dataset).unwrap(),
            [] as [ffs_zfs::ZfsUnlinkedObject; 0]
        );
        let mut head = engine
            .open_read_objects(&cx)
            .unwrap()
            .zpl(&cx, &dataset)
            .unwrap();
        assert!(head.stat(&cx, pending[0].object).is_err());
        let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
        assert_eq!(
            snapshot.read(&cx, pending[0].object, 0, 8192).unwrap(),
            original
        );
        assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, None);
    }
}

#[test]
fn cancelled_or_failed_last_release_keeps_durable_reclamation_retryable() {
    let cx = Cx::for_testing();
    for cancelled_release in [true, false] {
        let (engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
        let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
        let mut scope = RequestScope::empty();
        let (file, handle, _) = fs
            .create_open(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("deferred"),
                0o600,
                0,
                0,
                libc::O_RDWR,
            )
            .unwrap();
        fs.write(&cx, &mut scope, file.ino, 0, b"recoverable")
            .unwrap();
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("deferred"))
            .unwrap();
        let token = fs.last_durable_token().unwrap().unwrap();
        let release_cx = Cx::for_testing();
        if cancelled_release {
            release_cx.cancel_with(
                asupersync::types::CancelKind::User,
                Some("last release cancelled"),
            );
        } else {
            let call_index = devices[0].write_calls();
            devices[0].set_fault(DeviceFault::FailWriteOnCall { call_index });
        }
        let error = fs
            .release(
                &release_cx,
                &mut scope,
                ReleaseRequest {
                    ino: file.ino,
                    fh: handle,
                    flags: libc::O_RDWR,
                    lock_owner: None,
                    flush: false,
                },
            )
            .unwrap_err();
        assert_eq!(
            error.to_errno(),
            if cancelled_release {
                libc::EINTR
            } else {
                libc::EIO
            }
        );
        assert_eq!(fs.last_durable_token().unwrap().unwrap(), token);
        assert_eq!(read(&fs, &cx, file.ino), b"recoverable");
        assert_eq!(
            fs.flush(&cx, &mut scope, file.ino, handle, 0)
                .unwrap_err()
                .to_errno(),
            libc::EBADF
        );
        devices[0].set_fault(DeviceFault::None);
        fs.sync_fs(&cx, &mut scope).unwrap();
        assert!(fs.getattr(&cx, &mut scope, file.ino).is_err());
        assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
    }
}

#[test]
fn invalid_create_open_flags_are_rejected_before_namespace_mutation() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    let before = io_counts(&devices);
    for (flags, expected) in [
        (libc::O_ACCMODE, libc::EINVAL),
        (libc::O_DIRECTORY, libc::ENOTDIR),
    ] {
        assert_eq!(
            fs.create_open(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("rejected"),
                0o600,
                0,
                0,
                flags
            )
            .unwrap_err()
            .to_errno(),
            expected
        );
        assert!(
            fs.lookup(&cx, &mut scope, ROOT, OsStr::new("rejected"))
                .is_err()
        );
    }
    assert_eq!(io_counts(&devices), before);
    assert!(fs.last_durable_token().unwrap().is_none());
}

#[test]
fn failed_release_still_drops_the_backend_lifetime_pin() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    let (file, handle, _) = fs
        .create_open(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("cancelled-release"),
            0o600,
            0,
            0,
            libc::O_RDWR,
        )
        .unwrap();
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(
        asupersync::types::CancelKind::User,
        Some("release cancelled"),
    );
    assert!(matches!(
        fs.begin_request_scope(&cancelled, RequestOp::Create),
        Err(FfsError::Cancelled)
    ));
    let mut release_scope = fs
        .begin_request_scope(&cancelled, RequestOp::Release)
        .unwrap();
    assert!(matches!(
        fs.release(
            &cancelled,
            &mut release_scope,
            ReleaseRequest {
                ino: file.ino,
                fh: handle,
                flags: libc::O_RDWR,
                lock_owner: None,
                flush: false,
            }
        ),
        Err(FfsError::Cancelled)
    ));
    fs.end_request_scope(&cancelled, RequestOp::Release, release_scope)
        .unwrap();
    fs.unlink(&cx, &mut scope, ROOT, OsStr::new("cancelled-release"))
        .unwrap();

    let (file, handle, _) = fs
        .create_open(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("failed-flush"),
            0o600,
            0,
            0,
            libc::O_RDWR,
        )
        .unwrap();
    let sync_index = devices[0].state.lock().unwrap().sync_calls;
    devices[0].set_fault(DeviceFault::FailSyncOnCall { sync_index });
    assert!(
        fs.release(
            &cx,
            &mut scope,
            ReleaseRequest {
                ino: file.ino,
                fh: handle,
                flags: libc::O_RDWR,
                lock_owner: None,
                flush: true,
            }
        )
        .is_err()
    );
    devices[0].set_fault(DeviceFault::None);
    fs.unlink(&cx, &mut scope, ROOT, OsStr::new("failed-flush"))
        .unwrap();
    assert_eq!(
        fs.release(
            &cx,
            &mut scope,
            ReleaseRequest {
                ino: file.ino,
                fh: handle,
                flags: libc::O_RDWR,
                lock_owner: None,
                flush: false,
            }
        )
        .unwrap_err()
        .to_errno(),
        libc::EBADF
    );
}

#[test]
fn removed_directory_references_cannot_operate_on_a_reused_native_object() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    let old = fs
        .mkdir(&cx, &mut scope, ROOT, OsStr::new("old"), 0o700, 0, 0)
        .unwrap();
    fs.readdir(&cx, &mut scope, old.ino, 0).unwrap();
    fs.install_open_handle_oracle(Arc::new(|_| 1));
    fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("old")).unwrap();
    let new = fs
        .mkdir(&cx, &mut scope, ROOT, OsStr::new("new"), 0o750, 0, 0)
        .unwrap();
    assert_ne!(new.ino, old.ino);
    assert_ne!(new.generation, old.generation);
    let before = io_counts(&devices);
    assert!(fs.readdir(&cx, &mut scope, old.ino, 0).is_err());
    assert!(
        fs.create(
            &cx,
            &mut scope,
            old.ino,
            OsStr::new("wrong-directory"),
            0o600,
            0,
            0
        )
        .is_err()
    );
    assert_eq!(io_counts(&devices), before);
    assert!(
        fs.lookup(&cx, &mut scope, new.ino, OsStr::new("wrong-directory"))
            .is_err()
    );
    assert_eq!(lookup(&fs, &cx, new.ino, "..").ino, ROOT);
}

#[test]
fn writable_head_keeps_named_snapshots_immutable_and_read_only() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(
        &cx,
        &PoolFixtureSpec {
            deadlist_mode: DeadlistMode::NativeDeadlist,
            ..PoolFixtureSpec::default()
        },
    );
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    let head = lookup(&fs, &cx, ROOT, "hello.txt");
    let control = lookup(&fs, &cx, ROOT, ".zfs");
    let snapshots = lookup(&fs, &cx, control.ino, "snapshot");
    let before = lookup(&fs, &cx, snapshots.ino, "before");
    let historical = lookup(&fs, &cx, before.ino, "hello.txt");
    let original = read(&fs, &cx, historical.ino);
    assert_eq!(original, b"SNAPDATA".repeat(512));
    assert_eq!(historical.perm & 0o222, 0);
    fs.write(&cx, &mut scope, head.ino, 0, b"changed live bytes")
        .unwrap();
    fs.setattr(
        &cx,
        &mut scope,
        head.ino,
        &SetAttrRequest {
            size: Some(18),
            ..SetAttrRequest::default()
        },
    )
    .unwrap();
    assert_eq!(read(&fs, &cx, head.ino), b"changed live bytes");
    assert_eq!(read(&fs, &cx, historical.ino), original);
    let counts = io_counts(&devices);
    assert_eq!(
        fs.write(&cx, &mut scope, historical.ino, 0, b"forbidden")
            .unwrap_err()
            .to_errno(),
        libc::EROFS
    );
    assert_eq!(
        fs.removexattr(&cx, &mut scope, historical.ino, "security.capability")
            .unwrap_err()
            .to_errno(),
        libc::EROFS
    );
    assert_eq!(
        fs.create(
            &cx,
            &mut scope,
            before.ino,
            OsStr::new("forbidden"),
            0o600,
            0,
            0
        )
        .unwrap_err()
        .to_errno(),
        libc::EROFS
    );
    assert_eq!(
        fs.link(
            &cx,
            &mut scope,
            historical.ino,
            ROOT,
            OsStr::new("forbidden")
        )
        .unwrap_err()
        .to_errno(),
        libc::EROFS
    );
    assert_eq!(
        fs.rename(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("hello.txt"),
            before.ino,
            OsStr::new("forbidden")
        )
        .unwrap_err()
        .to_errno(),
        libc::EROFS
    );
    assert_eq!(io_counts(&devices), counts);
    let token = fs.last_durable_token().unwrap().unwrap();
    assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, Some(token.published_slot()));
}

#[test]
#[allow(clippy::too_many_lines)]
fn snapshot_destroy_preserves_live_handles_across_rename_and_cancelled_release() {
    let cx = Cx::for_testing();
    for (zpl_version, mirror_width, ashift) in [(4, 1, 9), (5, 2, 12)] {
        let (engine, devices) = writer_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                mirror_width,
                ashift,
                image_bytes: 32 * 1024 * 1024,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                ..PoolFixtureSpec::default()
            },
        );
        let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
        let mut scope = RequestScope::empty();
        let head = create(&fs, &cx, ROOT, "retained.bin");
        let old_bytes = vec![0x41; 65_536];
        let new_bytes = vec![0x42; 65_536];
        fs.write(&cx, &mut scope, head.ino, 0, &old_bytes).unwrap();
        fs.create_snapshot(&cx, b"pinned").unwrap();
        let control = lookup(&fs, &cx, ROOT, ".zfs");
        let snapshots = lookup(&fs, &cx, control.ino, "snapshot");
        let snapshot = lookup(&fs, &cx, snapshots.ino, "pinned");
        let historical = lookup(&fs, &cx, snapshot.ino, "retained.bin");
        let (first, _) = fs
            .open(&cx, &mut scope, historical.ino, libc::O_RDONLY)
            .unwrap();
        let (second, _) = fs
            .open(&cx, &mut scope, historical.ino, libc::O_RDONLY)
            .unwrap();
        assert_ne!(first, 0);
        assert_ne!(first, second);

        // A handle pins its own immutable view, not the entire dataset. A
        // separately named snapshot remains destroyable, and head COW must
        // preserve both the live bytes and the pinned historical payload.
        fs.create_snapshot(&cx, b"unrelated").unwrap();
        fs.write(&cx, &mut scope, head.ino, 0, &new_bytes).unwrap();
        fs.destroy_snapshot(&cx, b"unrelated", false).unwrap();
        assert_eq!(read(&fs, &cx, head.ino), new_bytes);
        assert_eq!(read(&fs, &cx, historical.ino), old_bytes);

        let assert_pinned = |name: &[u8]| {
            let before_io = io_counts(&devices);
            let before_token = fs.last_durable_token().unwrap().unwrap();
            let before_durable: Vec<_> = devices
                .iter()
                .map(|device| blake3::hash(&device.durable_snapshot()))
                .collect();
            for defer in [false, true] {
                assert_eq!(
                    fs.destroy_snapshot(&cx, name, defer)
                        .unwrap_err()
                        .to_errno(),
                    libc::EBUSY,
                    "neither normal nor deferred destruction may reclaim an open snapshot"
                );
                assert_eq!(io_counts(&devices), before_io);
                assert_eq!(
                    fs.last_durable_token().unwrap().unwrap().committed_txg(),
                    before_token.committed_txg(),
                    "a refused destruction must not publish a TXG"
                );
                for (device, expected) in devices.iter().zip(&before_durable) {
                    assert_eq!(blake3::hash(&device.durable_snapshot()), *expected);
                }
                assert_eq!(read(&fs, &cx, historical.ino), old_bytes);
            }
        };
        assert_pinned(b"pinned");
        fs.rename_snapshot(&cx, b"pinned", b"renamed").unwrap();
        let renamed = lookup(&fs, &cx, snapshots.ino, "renamed");
        assert_eq!(renamed.ino, snapshot.ino);
        assert_eq!(
            lookup(&fs, &cx, renamed.ino, "retained.bin").ino,
            historical.ino
        );
        assert_eq!(
            fs.destroy_snapshot(&cx, b"pinned", false)
                .unwrap_err()
                .to_errno(),
            libc::ENOENT
        );
        assert_pinned(b"renamed");

        release(&fs, &cx, historical.ino, first);
        assert_pinned(b"renamed");
        // A forged release for a different inode must not drop the remaining
        // pin, even though its numeric handle exists.
        assert_eq!(
            fs.release(
                &cx,
                &mut scope,
                ReleaseRequest {
                    ino: head.ino,
                    fh: second,
                    flags: libc::O_RDONLY,
                    lock_owner: None,
                    flush: false,
                },
            )
            .unwrap_err()
            .to_errno(),
            libc::EBADF
        );
        assert_pinned(b"renamed");
        fs.fsync(&cx, &mut scope, historical.ino, second, false)
            .unwrap();

        let cancelled = Cx::for_testing();
        cancelled.cancel_with(
            asupersync::types::CancelKind::User,
            Some("snapshot release cancelled"),
        );
        let mut release_scope = fs
            .begin_request_scope(&cancelled, RequestOp::Release)
            .unwrap();
        assert!(matches!(
            fs.release(
                &cancelled,
                &mut release_scope,
                ReleaseRequest {
                    ino: historical.ino,
                    fh: second,
                    flags: libc::O_RDONLY,
                    lock_owner: None,
                    flush: false,
                },
            ),
            Err(FfsError::Cancelled)
        ));
        fs.end_request_scope(&cancelled, RequestOp::Release, release_scope)
            .unwrap();
        let before_free = fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free;
        fs.destroy_snapshot(&cx, b"renamed", false).unwrap();
        assert!(fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free > before_free);
        assert!(matches!(
            fs.getattr(&cx, &mut scope, historical.ino),
            Err(FfsError::NotFound(_))
        ));
        assert_eq!(read(&fs, &cx, head.ino), new_bytes);

        fs.create_snapshot(&cx, b"renamed").unwrap();
        let recreated = lookup(&fs, &cx, snapshots.ino, "renamed");
        assert_ne!(recreated.ino, snapshot.ino);
        let current = lookup(&fs, &cx, recreated.ino, "retained.bin");
        assert_eq!(read(&fs, &cx, current.ino), new_bytes);
        // LOOKUP alone is not an open lifetime pin, nor may an obsolete handle
        // from the previous GUID protect the recreated snapshot.
        fs.destroy_snapshot(&cx, b"renamed", false).unwrap();
        let token = fs.last_durable_token().unwrap().unwrap();
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &devices,
            POOL_GUID,
            Some(token.published_slot()),
        );
        let reopened_devices: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let reopened = open_engine_on_devices(
            &cx,
            &reopened_devices,
            default_write_opts(POOL_GUID, token.published_slot()),
        )
        .unwrap();
        let mut objects = reopened.open_read_objects(&cx).unwrap();
        let dataset = [b"data".to_vec()];
        assert_eq!(objects.snapshots(&cx, &dataset).unwrap().len(), 1);
        let mut view = objects.zpl(&cx, &dataset).unwrap();
        let object = view.resolve(&cx, b"/retained.bin").unwrap();
        assert_eq!(view.read(&cx, object, 0, 65_536).unwrap(), new_bytes);
    }
}

#[test]
fn read_only_open_pins_snapshot_after_a_durable_rename_with_cancelled_refresh() {
    let cx = Cx::for_testing();
    let (mut engine, devices) = writer_fixture(
        &cx,
        &PoolFixtureSpec {
            deadlist_mode: DeadlistMode::NativeDeadlist,
            ..PoolFixtureSpec::default()
        },
    );
    let dataset = vec![b"data".to_vec()];
    let immutable = ZfsFs::new(
        &cx,
        engine
            .open_read_objects(&cx)
            .unwrap()
            .zpl(&cx, &dataset)
            .unwrap(),
        0,
        0,
    )
    .unwrap();
    let read_only_file = lookup(&immutable, &cx, ROOT, "hello.txt");
    assert_eq!(
        immutable
            .open_read_only(&cx, read_only_file.ino, libc::O_RDONLY)
            .unwrap(),
        (0, 0),
        "an immutable owner retains its stateless open contract"
    );
    drop(immutable);

    let rename_cx = Cx::for_testing();
    let cancel_rename = rename_cx.clone();
    engine.with_fault_hook(move |event| {
        if event.operation == "rename_snapshot"
            && event.stage == ZfsPersistenceStage::BeforeAcknowledge
        {
            cancel_rename.cancel_with(
                asupersync::types::CancelKind::User,
                Some("snapshot rename committed before cancellation"),
            );
        }
        Ok(())
    });
    let fs = ZfsFs::with_writer(&cx, engine, dataset).unwrap();
    let mut scope = RequestScope::empty();
    let control = lookup(&fs, &cx, ROOT, ".zfs");
    let snapshots = lookup(&fs, &cx, control.ino, "snapshot");
    let snapshot = lookup(&fs, &cx, snapshots.ino, "before");
    let historical = lookup(&fs, &cx, snapshot.ino, "hello.txt");
    let (handle, _) = fs
        .open_read_only(&cx, historical.ino, libc::O_RDONLY)
        .unwrap();
    assert_ne!(
        handle, 0,
        "read-only opens on a writer must retain lifetime pins"
    );
    assert!(matches!(
        fs.rename_snapshot(&rename_cx, b"before", b"renamed"),
        Err(FfsError::Cancelled)
    ));
    let token = fs.last_durable_token().unwrap().unwrap();
    assert_eq!(token.committed_txg(), INITIAL_TXG + 1);

    // Do not look up the renamed entry first: the mount's cached directory
    // still has the old name. Reclamation must resolve committed GUID identity
    // rather than let that interrupted refresh hide an existing open handle.
    let before_io = io_counts(&devices);
    assert_eq!(
        fs.destroy_snapshot(&cx, b"renamed", false)
            .unwrap_err()
            .to_errno(),
        libc::EBUSY
    );
    assert_eq!(io_counts(&devices), before_io);
    assert_eq!(
        fs.last_durable_token().unwrap().unwrap().committed_txg(),
        token.committed_txg()
    );
    assert_eq!(read(&fs, &cx, historical.ino), b"SNAPDATA".repeat(512));
    release(&fs, &cx, historical.ino, handle);
    fs.destroy_snapshot(&cx, b"renamed", false).unwrap();
    assert!(matches!(
        fs.getattr(&cx, &mut scope, historical.ino),
        Err(FfsError::NotFound(_))
    ));
    let token = fs.last_durable_token().unwrap().unwrap();
    assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, Some(token.published_slot()));
}

#[test]
fn cancelled_snapshot_destroy_reconciles_catalog_before_reopening_stale_inodes() {
    let cx = Cx::for_testing();
    let (mut engine, devices) = writer_fixture(
        &cx,
        &PoolFixtureSpec {
            deadlist_mode: DeadlistMode::NativeDeadlist,
            ..PoolFixtureSpec::default()
        },
    );
    let destroy_cx = Cx::for_testing();
    let cancel_destroy = destroy_cx.clone();
    engine.with_fault_hook(move |event| {
        if event.operation == "destroy_snapshot"
            && event.stage == ZfsPersistenceStage::BeforeAcknowledge
        {
            cancel_destroy.cancel_with(
                asupersync::types::CancelKind::User,
                Some("snapshot destroy committed before cancellation"),
            );
        }
        Ok(())
    });
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    let control = lookup(&fs, &cx, ROOT, ".zfs");
    let snapshots = lookup(&fs, &cx, control.ino, "snapshot");
    let before = lookup(&fs, &cx, snapshots.ino, "before");
    let historical = lookup(&fs, &cx, before.ino, "hello.txt");
    // A cached LOOKUP without OPEN does not pin the snapshot. Its stale inode
    // must become unusable as soon as the committed destroy is observed.
    assert!(matches!(
        fs.destroy_snapshot(&destroy_cx, b"before", false),
        Err(FfsError::Cancelled)
    ));
    let destroyed = fs.last_durable_token().unwrap().unwrap();
    assert_eq!(destroyed.committed_txg(), INITIAL_TXG + 1);
    let before_io = io_counts(&devices);
    assert!(matches!(
        fs.open(&cx, &mut scope, historical.ino, libc::O_RDONLY),
        Err(FfsError::NotFound(_))
    ));
    assert!(matches!(
        fs.open_read_only(&cx, historical.ino, libc::O_RDONLY),
        Err(FfsError::NotFound(_))
    ));
    assert!(matches!(
        fs.read(&cx, &mut scope, historical.ino, 0, 8192),
        Err(FfsError::NotFound(_))
    ));
    assert!(matches!(
        fs.lookup(&cx, &mut scope, snapshots.ino, OsStr::new("before")),
        Err(FfsError::NotFound(_))
    ));
    assert_eq!(io_counts(&devices), before_io);
    assert_eq!(
        fs.last_durable_token().unwrap().unwrap().committed_txg(),
        destroyed.committed_txg()
    );

    // Reusing the old catalog name publishes a distinct GUID/index. Even
    // after allocating new head data, the destroyed inode must stay stale.
    let head = lookup(&fs, &cx, ROOT, "hello.txt");
    let new_bytes = vec![0x5A; 65_536];
    fs.write(&cx, &mut scope, head.ino, 0, &new_bytes).unwrap();
    fs.create_snapshot(&cx, b"before").unwrap();
    let recreated = lookup(&fs, &cx, snapshots.ino, "before");
    assert_ne!(recreated.ino, before.ino);
    let current = lookup(&fs, &cx, recreated.ino, "hello.txt");
    assert_ne!(current.ino, historical.ino);
    assert_eq!(read(&fs, &cx, current.ino), new_bytes);
    assert!(matches!(
        fs.open(&cx, &mut scope, historical.ino, libc::O_RDONLY),
        Err(FfsError::NotFound(_))
    ));
    let token = fs.last_durable_token().unwrap().unwrap();
    assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, Some(token.published_slot()));
}

#[test]
fn writable_mount_admission_refuses_inherited_readonly_and_uncertain_owners() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(
        &cx,
        &PoolFixtureSpec {
            root_properties: vec![(b"readonly", 1)],
            ..PoolFixtureSpec::default()
        },
    );
    assert!(matches!(
        ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]),
        Err(FfsError::ReadOnly)
    ));
    assert!(io_counts(&devices).iter().all(|&count| count == (0, 0)));

    let (mut engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
    engine.with_fault_hook(|event| {
        if matches!(
            event.stage,
            ZfsPersistenceStage::UberblockWrite { label: 2, .. }
        ) {
            return Err(FfsError::Cancelled);
        }
        Ok(())
    });
    assert!(matches!(
        engine.mkdir(
            &cx,
            &[b"data".to_vec()],
            2,
            b"uncertain",
            0o755,
            0,
            0,
            Timestamp {
                seconds: 1_715_000_000,
                nanos: 0
            }
        ),
        ZfsTxOutcome::Uncertain { .. }
    ));
    let counts = io_counts(&devices);
    assert!(ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).is_err());
    assert_eq!(io_counts(&devices), counts);
}

#[test]
fn uncertain_commit_poisoning_prevents_stale_reads_writes_and_false_fsync_success() {
    let cx = Cx::for_testing();
    let (mut engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
    let armed = Arc::new(AtomicBool::new(false));
    let hook_armed = Arc::clone(&armed);
    engine.with_fault_hook(move |event| {
        if hook_armed.load(Ordering::SeqCst)
            && matches!(
                event.stage,
                ZfsPersistenceStage::UberblockWrite { label: 2, .. }
            )
        {
            return Err(FfsError::Cancelled);
        }
        Ok(())
    });
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    let file = create(&fs, &cx, ROOT, "known");
    fs.write(&cx, &mut scope, file.ino, 0, b"old").unwrap();
    let previous = fs.last_durable_token().unwrap().unwrap();
    armed.store(true, Ordering::SeqCst);
    assert!(fs.write(&cx, &mut scope, file.ino, 0, b"new").is_err());
    let counts = io_counts(&devices);
    assert_eq!(
        fs.read(&cx, &mut scope, file.ino, 0, 10)
            .unwrap_err()
            .to_errno(),
        libc::EIO
    );
    assert_eq!(
        fs.write(&cx, &mut scope, file.ino, 0, b"again")
            .unwrap_err()
            .to_errno(),
        libc::EIO
    );
    assert_eq!(
        fs.getattr(&cx, &mut scope, ROOT).unwrap_err().to_errno(),
        libc::EIO
    );
    assert_eq!(
        fs.fsync(&cx, &mut scope, file.ino, 0, false)
            .unwrap_err()
            .to_errno(),
        libc::EIO
    );
    assert_eq!(fs.flush_on_destroy(&cx).unwrap_err().to_errno(), libc::EIO);
    assert_eq!(fs.last_durable_token().unwrap().unwrap(), previous);
    assert_eq!(io_counts(&devices), counts);
}

#[test]
fn late_cancellation_preserves_durable_token_and_refreshes_on_the_next_request() {
    let cx = Cx::for_testing();
    let (mut engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
    let cancelled = cx.clone();
    let once = Arc::new(AtomicBool::new(true));
    engine.with_fault_hook(move |event| {
        if event.stage == ZfsPersistenceStage::BeforeAcknowledge
            && once.swap(false, Ordering::SeqCst)
        {
            cancelled.cancel_with(
                asupersync::types::CancelKind::User,
                Some("after native commit"),
            );
        }
        Ok(())
    });
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    assert!(matches!(
        fs.create_open(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("durable"),
            0o600,
            0,
            0,
            libc::O_CREAT | libc::O_RDWR
        ),
        Err(FfsError::Cancelled)
    ));
    let token = fs.last_durable_token().unwrap().unwrap();
    assert_eq!(token.committed_txg(), INITIAL_TXG + 1);
    let next = Cx::for_testing();
    let file = lookup(&fs, &next, ROOT, "durable");
    fs.write(&next, &mut scope, file.ino, 0, b"usable after cancellation")
        .unwrap();
    assert_eq!(read(&fs, &next, file.ino), b"usable after cancellation");
    // CREATE returned an error before delivering a handle, so it must leave
    // no abandoned lifetime pin despite having committed the native name.
    fs.unlink(&next, &mut scope, ROOT, OsStr::new("durable"))
        .unwrap();
    assert_pool_scrub_and_allocation_clean(&next, &devices, POOL_GUID, None);
}

#[test]
fn fsync_propagates_member_flush_failures_after_a_known_commit_and_can_retry() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(
        &cx,
        &PoolFixtureSpec {
            mirror_width: 2,
            ..PoolFixtureSpec::default()
        },
    );
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    let file = create(&fs, &cx, ROOT, "synced");
    fs.write(&cx, &mut scope, file.ino, 0, b"already durable")
        .unwrap();
    let token = fs.last_durable_token().unwrap().unwrap();
    let sync_index = devices[1].state.lock().unwrap().sync_calls;
    devices[1].set_fault(DeviceFault::FailSyncOnCall { sync_index });
    assert!(fs.fsync(&cx, &mut scope, file.ino, 0, false).is_err());
    assert_eq!(fs.last_durable_token().unwrap().unwrap(), token);
    devices[1].set_fault(DeviceFault::None);
    fs.fsync(&cx, &mut scope, file.ino, 0, false).unwrap();
    fs.sync_fs(&cx, &mut scope).unwrap();
    assert_eq!(read(&fs, &cx, file.ino), b"already durable");
}

#[test]
fn data_mutations_refuse_set_id_files_before_commit_and_do_not_leak_handles() {
    let cx = Cx::for_testing();
    for mode in [0o4755, 0o2755] {
        let (mut engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
        let dataset = vec![b"data".to_vec()];
        let timestamp = Timestamp {
            seconds: 1_715_000_000,
            nanos: 0,
        };
        let payload = b"privileged contents must survive refusal";
        // The explicit image editor can seed privileged native data. The mounted
        // profile cannot modify it until atomic privilege clearing is implemented.
        let (object, _) = engine
            .create_file(
                &cx,
                &dataset,
                2,
                b"privileged",
                mode,
                1234,
                5678,
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        engine
            .write_file_data(
                &cx,
                &dataset,
                object,
                0,
                payload,
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let fs = ZfsFs::with_writer(&cx, engine, dataset).unwrap();
        let mut scope = RequestScope::empty();
        let file = lookup(&fs, &cx, ROOT, "privileged");
        assert_eq!(file.perm, mode);
        assert_eq!(read(&fs, &cx, file.ino), payload);
        let source = create(&fs, &cx, ROOT, "source");
        let replacement = b"replacement bytes";
        fs.write(&cx, &mut scope, source.ino, 0, replacement)
            .unwrap();
        let ordinary = create(&fs, &cx, ROOT, "ordinary");
        assert_eq!(
            fs.copy_file_range(
                &cx,
                &mut scope,
                source.ino,
                0,
                ordinary.ino,
                0,
                replacement.len() as u64
            )
            .unwrap(),
            replacement.len() as u64
        );
        assert_eq!(read(&fs, &cx, ordinary.ino), replacement);
        let (handle, _) = fs.open(&cx, &mut scope, file.ino, libc::O_RDONLY).unwrap();
        release(&fs, &cx, file.ino, handle);
        let token = fs.last_durable_token().unwrap().unwrap();
        let before = io_counts(&devices);
        assert_eq!(
            fs.setattr(
                &cx,
                &mut scope,
                file.ino,
                &SetAttrRequest {
                    size: Some(0),
                    ..SetAttrRequest::default()
                }
            )
            .unwrap_err()
            .to_errno(),
            libc::EOPNOTSUPP
        );
        assert_eq!(
            fs.open(&cx, &mut scope, file.ino, libc::O_WRONLY | libc::O_TRUNC)
                .unwrap_err()
                .to_errno(),
            libc::EOPNOTSUPP
        );
        assert_eq!(
            fs.write(&cx, &mut scope, file.ino, 0, replacement)
                .unwrap_err()
                .to_errno(),
            libc::EOPNOTSUPP
        );
        assert_eq!(
            fs.copy_file_range(
                &cx,
                &mut scope,
                source.ino,
                0,
                file.ino,
                0,
                replacement.len() as u64
            )
            .unwrap_err()
            .to_errno(),
            libc::EOPNOTSUPP
        );
        assert_eq!(io_counts(&devices), before);
        assert_eq!(fs.last_durable_token().unwrap().unwrap(), token);
        assert_eq!(read(&fs, &cx, file.ino), payload);
        let unchanged = fs.getattr(&cx, &mut scope, file.ino).unwrap();
        assert_eq!(
            (unchanged.perm, unchanged.size),
            (mode, payload.len() as u64)
        );
        let (next_handle, _) = fs.open(&cx, &mut scope, file.ino, libc::O_RDONLY).unwrap();
        assert_eq!(next_handle, handle + 1);
        release(&fs, &cx, file.ino, next_handle);
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("privileged"))
            .unwrap();
    }
}

#[test]
fn native_reclamation_refuses_external_owners_without_writes() {
    use ffs_ondisk::zfs_zpl::ReclamationOwnership;

    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_400,
        nanos: 23,
    };
    let unowned = ReclamationOwnership {
        xattr_directory: 0,
        external_acl_object: 0,
        project_id: 0,
    };
    for zpl_version in [4, 5] {
        for ownership in [
            ReclamationOwnership {
                xattr_directory: 6,
                ..unowned
            },
            ReclamationOwnership {
                external_acl_object: 42,
                ..unowned
            },
        ] {
            let (mut engine, devices) = writer_fixture(
                &cx,
                &PoolFixtureSpec {
                    zpl_version,
                    hello_ownership: Some(ownership),
                    deadlist_mode: DeadlistMode::NativeDeadlist,
                    ..PoolFixtureSpec::default()
                },
            );
            let mut head = engine
                .open_read_objects(&cx)
                .unwrap()
                .zpl(&cx, &dataset)
                .unwrap();
            let object = head.resolve(&cx, b"/hello.txt").unwrap();
            let source = head.resolve(&cx, b"/keep.bin").unwrap();
            let payload = head.read(&cx, object, 0, 8192).unwrap();
            let identity = ZfsUnlinkedObject {
                object,
                generation: head.stat(&cx, object).unwrap().0.generation,
            };
            assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
                writer.unlink_open_file(&cx, &dataset, 2, b"hello.txt", identity, timestamp)
            });
            assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
                writer.rename_retaining_open_target(
                    &cx,
                    &dataset,
                    2,
                    b"keep.bin",
                    2,
                    b"hello.txt",
                    Some(source),
                    identity,
                    timestamp,
                )
            });
            assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
                writer.unlink_entry(&cx, &dataset, 2, b"hello.txt", false, timestamp)
            });
            assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
                writer.rename_entry(
                    &cx,
                    &dataset,
                    2,
                    b"keep.bin",
                    2,
                    b"hello.txt",
                    Some(source),
                    timestamp,
                )
            });
            assert_eq!(
                engine.pending_unlinks(&cx, &dataset).unwrap(),
                [] as [ffs_zfs::ZfsUnlinkedObject; 0]
            );
            let mut head = engine
                .open_read_objects(&cx)
                .unwrap()
                .zpl(&cx, &dataset)
                .unwrap();
            assert_eq!(head.resolve(&cx, b"/hello.txt").unwrap(), object);
            assert_eq!(head.resolve(&cx, b"/keep.bin").unwrap(), source);
            assert_eq!(head.read(&cx, object, 0, 8192).unwrap(), payload);

            // A nonfinal link removal keeps all native ownership intact and
            // remains supported even when final reclamation is not admitted.
            engine
                .link_entry(&cx, &dataset, object, 2, b"alias", timestamp)
                .into_result()
                .unwrap();
            engine
                .unlink_entry(&cx, &dataset, 2, b"alias", false, timestamp)
                .into_result()
                .unwrap();
            let mut head = engine
                .open_read_objects(&cx)
                .unwrap()
                .zpl(&cx, &dataset)
                .unwrap();
            assert_eq!(head.stat(&cx, object).unwrap().0.links, 1);
            assert_eq!(head.resolve(&cx, b"/hello.txt").unwrap(), object);
            assert_eq!(head.read(&cx, object, 0, 8192).unwrap(), payload);
        }
    }
}

#[test]
fn mount_admission_precedes_durable_orphan_cleanup() {
    let cx = Cx::for_testing();
    let dataset = vec![b"data".to_vec()];
    let out_of_range = u64::from(u32::MAX) + 1;
    let timestamp = Timestamp {
        seconds: 1_715_000_401,
        nanos: 29,
    };
    for zpl_version in [4, 5] {
        for root_ids in [(out_of_range, 0), (0, out_of_range)] {
            let (mut engine, devices) = writer_fixture(
                &cx,
                &PoolFixtureSpec {
                    zpl_version,
                    root_ids,
                    deadlist_mode: DeadlistMode::NativeDeadlist,
                    ..PoolFixtureSpec::default()
                },
            );
            let mut head = engine
                .open_read_objects(&cx)
                .unwrap()
                .zpl(&cx, &dataset)
                .unwrap();
            let object = head.resolve(&cx, b"/hello.txt").unwrap();
            let identity = ZfsUnlinkedObject {
                object,
                generation: head.stat(&cx, object).unwrap().0.generation,
            };
            let payload = head.read(&cx, object, 0, 8192).unwrap();
            let (_, token) = engine
                .unlink_open_file(&cx, &dataset, 2, b"hello.txt", identity, timestamp)
                .into_result()
                .unwrap();
            let before = io_counts(&devices);
            let error = ZfsFs::with_writer(&cx, engine, dataset.clone())
                .err()
                .expect("unrepresentable root identity must refuse mounting");
            assert_eq!(error.to_errno(), libc::EOVERFLOW);
            assert_eq!(
                io_counts(&devices),
                before,
                "mount admission refusal reclaimed storage"
            );

            let recovered = open_engine_on_devices(
                &cx,
                &devices,
                default_write_opts(POOL_GUID, token.published_slot()),
            )
            .unwrap();
            assert_eq!(
                recovered.pending_unlinks(&cx, &dataset).unwrap(),
                vec![identity]
            );
            let mut head = recovered
                .open_read_objects(&cx)
                .unwrap()
                .zpl(&cx, &dataset)
                .unwrap();
            assert_eq!(head.stat(&cx, object).unwrap().0.links, 0);
            assert_eq!(head.read(&cx, object, 0, 8192).unwrap(), payload);
        }
    }
}

#[test]
fn file_range_fsops_support_sparse_modes_and_keep_snapshots_read_only() {
    let cx = Cx::for_testing();
    let (engine, devices) = writer_fixture(
        &cx,
        &PoolFixtureSpec {
            ashift: 12,
            deadlist_mode: DeadlistMode::NativeDeadlist,
            data_properties: vec![(b"recordsize", 4096)],
            image_bytes: 24 * 1024 * 1024,
            ..PoolFixtureSpec::default()
        },
    );
    let fs = ZfsFs::with_writer(&cx, engine, vec![b"data".to_vec()]).unwrap();
    let mut scope = RequestScope::empty();
    let file = lookup(&fs, &cx, ROOT, "hello.txt");
    let payload = vec![0x6B; 6 * 4096 + 17];
    fs.write(&cx, &mut scope, file.ino, 0, &payload).unwrap();
    fs.create_snapshot(&cx, b"range-view").unwrap();
    let control = lookup(&fs, &cx, ROOT, ".zfs");
    let snapshots = lookup(&fs, &cx, control.ino, "snapshot");
    let snapshot = lookup(&fs, &cx, snapshots.ino, "range-view");
    let historical = lookup(&fs, &cx, snapshot.ino, "hello.txt");
    let before = fs.getattr(&cx, &mut scope, file.ino).unwrap();

    fs.fallocate(
        &cx,
        &mut scope,
        file.ino,
        31,
        3 * 4096 + 61,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
    )
    .unwrap();
    let mut expected = payload.clone();
    expected[31..3 * 4096 + 92].fill(0);
    assert_eq!(read(&fs, &cx, file.ino), expected);
    let punched = fs.getattr(&cx, &mut scope, file.ino).unwrap();
    assert_eq!(punched.size, before.size);
    assert_eq!(punched.blocks, before.blocks - 2 * 4096 / 512);
    assert_eq!(punched.generation, before.generation);
    assert_eq!(read(&fs, &cx, historical.ino), payload);
    assert_eq!(
        fs.lseek(&cx, &mut scope, file.ino, 4096, ffs_core::SeekWhence::Data)
            .unwrap(),
        3 * 4096
    );

    let tail = expected.len() - 7;
    fs.fallocate(
        &cx,
        &mut scope,
        file.ino,
        tail as u64,
        8192,
        libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE,
    )
    .unwrap();
    expected[tail..].fill(0);
    assert_eq!(read(&fs, &cx, file.ino), expected);
    assert_eq!(
        fs.getattr(&cx, &mut scope, file.ino).unwrap().size,
        before.size
    );
    let extension = expected.len() + 4096;
    fs.fallocate(
        &cx,
        &mut scope,
        file.ino,
        extension as u64,
        17,
        libc::FALLOC_FL_ZERO_RANGE,
    )
    .unwrap();
    expected.resize(extension + 17, 0);
    assert_eq!(read(&fs, &cx, file.ino), expected);
    assert_eq!(
        fs.getattr(&cx, &mut scope, file.ino).unwrap().size,
        expected.len() as u64
    );

    let writes = io_counts(&devices);
    let token = fs.last_durable_token().unwrap().unwrap();
    for unsupported_mode in [
        0,
        libc::FALLOC_FL_KEEP_SIZE,
        libc::FALLOC_FL_PUNCH_HOLE,
        libc::FALLOC_FL_COLLAPSE_RANGE,
        libc::FALLOC_FL_INSERT_RANGE,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE,
        1 << 30,
    ] {
        assert_eq!(
            fs.fallocate(&cx, &mut scope, file.ino, 0, 4096, unsupported_mode)
                .unwrap_err()
                .to_errno(),
            libc::EOPNOTSUPP
        );
    }
    for (offset, length) in [(0, 0), (u64::MAX, 1), (i64::MAX as u64, 1)] {
        assert_eq!(
            fs.fallocate(
                &cx,
                &mut scope,
                file.ino,
                offset,
                length,
                libc::FALLOC_FL_ZERO_RANGE
            )
            .unwrap_err()
            .to_errno(),
            libc::EINVAL
        );
    }
    assert_eq!(
        fs.fallocate(&cx, &mut scope, ROOT, 0, 4096, libc::FALLOC_FL_ZERO_RANGE)
            .unwrap_err()
            .to_errno(),
        libc::EISDIR
    );
    assert!(matches!(
        fs.fallocate(
            &cx,
            &mut scope,
            historical.ino,
            0,
            4096,
            libc::FALLOC_FL_ZERO_RANGE
        ),
        Err(FfsError::ReadOnly)
    ));
    assert_eq!(io_counts(&devices), writes);
    assert_eq!(fs.last_durable_token().unwrap().unwrap(), token);
    assert_eq!(read(&fs, &cx, file.ino), expected);
    assert_eq!(read(&fs, &cx, historical.ino), payload);

    let leaves = devices
        .iter()
        .map(|device| {
            let fresh = device.fresh_from_durable();
            let len = fresh.len_bytes();
            Leaf::from_device(&cx, Box::new(fresh), 0, len).unwrap()
        })
        .collect();
    let pool = Pool::from_leaves(leaves).unwrap();
    let view = pool
        .import_objects(&cx, Some(POOL_GUID))
        .unwrap()
        .zpl(&cx, &[b"data".to_vec()])
        .unwrap();
    let read_only = ZfsFs::new(&cx, view, 0, 0).unwrap();
    let cold_file = lookup(&read_only, &cx, ROOT, "hello.txt");
    assert_eq!(read(&read_only, &cx, cold_file.ino), expected);
    assert!(matches!(
        read_only.fallocate(
            &cx,
            &mut scope,
            cold_file.ino,
            0,
            4096,
            libc::FALLOC_FL_ZERO_RANGE
        ),
        Err(FfsError::ReadOnly)
    ));
    assert_eq!(io_counts(&devices), writes);
    assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
}

#[test]
fn file_range_fsops_late_cancellation_preserves_success_and_refreshes_next_request() {
    let cx = Cx::for_testing();
    let (mut engine, devices) = writer_fixture(&cx, &PoolFixtureSpec::default());
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_730_000_005,
        nanos: 0,
    };
    let (object, _) = engine
        .create_file(
            &cx,
            &dataset,
            2,
            b"hello.txt",
            0o644,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("create the file before exercising committed cancellation");
    engine
        .write_file_data(
            &cx,
            &dataset,
            object,
            0,
            b"abcdefghi",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    engine
        .truncate_file(
            &cx,
            &dataset,
            object,
            9,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let pre_txg = engine.committed_txg();
    let cancelled = cx.clone();
    let once = Arc::new(AtomicBool::new(true));
    engine.with_fault_hook(move |event| {
        if event.stage == ZfsPersistenceStage::BeforeAcknowledge
            && once.swap(false, Ordering::SeqCst)
        {
            cancelled.cancel_with(
                asupersync::types::CancelKind::User,
                Some("after sparse range commit"),
            );
        }
        Ok(())
    });
    let fs = ZfsFs::with_writer(&cx, engine, dataset.to_vec()).unwrap();
    let mut scope = RequestScope::empty();
    let file = lookup(&fs, &cx, ROOT, "hello.txt");
    fs.fallocate(
        &cx,
        &mut scope,
        file.ino,
        2,
        3,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
    )
    .expect("durable range mutation must retain success after cancellation");
    assert_eq!(
        fs.last_durable_token().unwrap().unwrap().committed_txg(),
        pre_txg + 1
    );
    let writes = io_counts(&devices);
    assert!(matches!(
        fs.fallocate(&cx, &mut scope, file.ino, 0, 9, libc::FALLOC_FL_ZERO_RANGE),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(io_counts(&devices), writes);
    let next = Cx::for_testing();
    assert_eq!(read(&fs, &next, file.ino), b"ab\0\0\0fghi");
    fs.write(&next, &mut scope, file.ino, 3, b"X").unwrap();
    assert_eq!(read(&fs, &next, file.ino), b"ab\0X\0fghi");
    assert_pool_scrub_and_allocation_clean(&next, &devices, POOL_GUID, None);
}
