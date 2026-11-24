//! Durable final-unlink ownership, native journal crash recovery, and refusal
//! controls for names or streams that do not authorize automatic deletion.

use std::ffi::OsStr;
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_core::vfs::ReleaseRequest;
use ffs_core::{FsOps, RequestScope, SetAttrRequest};
use ffs_error::FfsError;
use ffs_ntfs::formatter::{NtfsFormatOptions, NtfsFormatVersion, format_image_file};
use ffs_ntfs::reader::allocation::AllocationLimits;
use ffs_ntfs::transaction::{
    DEFAULT_NTFS_FILETIME, NtfsPersistenceStage, NtfsTransactionEngine, NtfsTxOutcome,
};
use ffs_ntfs::{NtfsFs, NtfsVolume};
use ffs_ondisk::ntfs::NtfsReference;
use ffs_types::InodeNumber;

use super::{
    FaultInjectingNtfsDevice, SECTOR_BYTES, build_clean_ntfs_image, write_options_recover,
};

const ROOT: InodeNumber = InodeNumber(1);
const MARKER: &str = "$FrankenFS.Orphan";
const PREFIX: &str = ".ffs-unlinked-";

fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn engine_for(cx: &Cx, device: &Arc<FaultInjectingNtfsDevice>) -> NtfsTransactionEngine {
    NtfsTransactionEngine::from_device(
        cx,
        Arc::clone(device) as Arc<dyn ByteDevice>,
        0,
        device.len_bytes() - SECTOR_BYTES as u64,
        write_options_recover(),
    )
    .unwrap()
}

fn synthetic_device() -> Arc<FaultInjectingNtfsDevice> {
    FaultInjectingNtfsDevice::new(build_clean_ntfs_image(512, 64, 0x0F12_0000_0000_0001))
}

fn native_stream(cx: &Cx, volume: &NtfsVolume, target: NtfsReference, stream: &str) -> Vec<u8> {
    let record = volume
        .record(cx, target.record, Some(target.sequence))
        .unwrap();
    let data = volume.data_stream(cx, &record, &utf16(stream)).unwrap();
    volume
        .read(cx, &data, 0, usize::try_from(data.size).unwrap())
        .unwrap()
}

fn owned_files(cx: &Cx, engine: &NtfsTransactionEngine) -> Vec<(NtfsReference, Vec<u16>)> {
    let volume = engine.volume_view(cx).unwrap();
    let root = volume.record(cx, 5, None).unwrap();
    volume
        .list_directory(cx, &root)
        .unwrap()
        .into_iter()
        .filter_map(|entry| {
            if !entry.filename.name.starts_with(&utf16(PREFIX)) {
                return None;
            }
            let record = volume
                .record(cx, entry.reference.record, Some(entry.reference.sequence))
                .unwrap();
            match volume.data_stream(cx, &record, &utf16(MARKER)) {
                Ok(stream) => {
                    assert!(stream.resident());
                    let bytes = volume.read(cx, &stream, 0, 256).unwrap();
                    assert_eq!(bytes.len(), 144);
                    assert_eq!(&bytes[..16], b"FFS_NTFS_ORPHAN\0");
                    assert_eq!(&bytes[16..24], &1_u64.to_le_bytes());
                    assert_eq!(
                        &bytes[24..32],
                        &engine.storage_identity().volume_serial.to_le_bytes()
                    );
                    assert_eq!(&bytes[32..64], &engine.storage_identity().boot_blake3);
                    assert_eq!(
                        &bytes[64..72],
                        &entry.reference.encode().unwrap().to_le_bytes()
                    );
                    let root_ref = NtfsReference {
                        record: 5,
                        sequence: root.sequence,
                    };
                    assert_eq!(&bytes[72..80], &root_ref.encode().unwrap().to_le_bytes());
                    let name_bytes: Vec<_> = entry
                        .filename
                        .name
                        .iter()
                        .flat_map(|unit| unit.to_le_bytes())
                        .collect();
                    assert_eq!(&bytes[80..112], blake3::hash(&name_bytes).as_bytes());
                    assert_eq!(&bytes[112..], blake3::hash(&bytes[..112]).as_bytes());
                    Some((entry.reference, entry.filename.name))
                }
                Err(FfsError::NotFound(_)) => None,
                Err(error) => panic!("cannot inspect retained native stream: {error:?}"),
            }
        })
        .collect()
}

fn release(fs: &NtfsFs, cx: &Cx, scope: &mut RequestScope, ino: InodeNumber, handle: u64) {
    fs.release(
        cx,
        scope,
        ReleaseRequest {
            ino,
            fh: handle,
            flags: libc::O_RDWR,
            lock_owner: None,
            flush: false,
        },
    )
    .unwrap();
}

fn retain_files(
    cx: &Cx,
    device: &Arc<FaultInjectingNtfsDevice>,
    count: usize,
) -> Vec<NtfsReference> {
    let mut engine = engine_for(cx, device);
    let mut references = Vec::new();
    for index in 0..count {
        references.push(
            engine
                .create_file(cx, "/", &format!("victim{index}"), &[0x61; 9000])
                .into_result()
                .unwrap()
                .0,
        );
    }
    let fs = NtfsFs::from_engine(cx, engine, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    for index in 0..count {
        let name = format!("victim{index}");
        let file = fs.lookup(cx, &mut scope, ROOT, OsStr::new(&name)).unwrap();
        fs.open(cx, &mut scope, file.ino, libc::O_RDWR).unwrap();
        fs.unlink(cx, &mut scope, ROOT, OsStr::new(&name)).unwrap();
    }
    // Lose the mount's in-memory handle table without a normal destroy flush.
    drop(fs);
    references
}

fn assert_mount_name_refusal_preserves_orphans(name: &[u16], expected_errno: i32) {
    let cx = Cx::for_testing();
    let device = synthetic_device();
    let retained = retain_files(&cx, &device, 1)[0];
    let mut engine = engine_for(&cx, &device);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    let ordinary = engine
        .create_entry_at(
            &cx,
            root,
            name,
            false,
            false,
            b"ordinary data",
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap()
        .0;
    engine.check_clean_consistency(&cx).unwrap();
    let ownership = owned_files(&cx, &engine);
    assert_eq!(ownership.len(), 1);
    assert_eq!(ownership[0].0, retained);
    let retained_name = String::from_utf16(&ownership[0].1).unwrap();
    let before = device.snapshot_durable_only();
    let writes = device.write_bytes_total();

    // This namespace is valid NTFS, but its exact native name cannot pass the
    // mounted host projection. Refusal must precede all orphan-recovery writes.
    let Err(error) = NtfsFs::from_engine(&cx, engine, 1000, 1000) else {
        panic!("unrepresentable native name was admitted for mounting");
    };
    assert_eq!(error.to_errno(), expected_errno);
    assert_eq!(
        device.write_bytes_total(),
        writes,
        "rejected mount reclaimed a file before validating its namespace"
    );
    assert_eq!(device.snapshot_live(), before);
    assert_eq!(device.snapshot_durable_only(), before);

    let mut engine = engine_for(&cx, &device);
    engine.check_clean_consistency(&cx).unwrap();
    assert_eq!(owned_files(&cx, &engine), ownership);
    let volume = engine.volume_view(&cx).unwrap();
    assert_eq!(native_stream(&cx, &volume, retained, ""), [0x61; 9000]);
    assert_eq!(native_stream(&cx, &volume, ordinary, ""), b"ordinary data");

    // A native rename removes the host-projection blocker. Admission can then
    // reap the orphan and must expose a fresh, writable view of the survivor.
    engine
        .rename_at(&cx, root, name, root, &utf16("ordinary"), ordinary, true)
        .into_result()
        .unwrap();
    let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
    assert!(fs.last_durable_token().unwrap().is_some());
    let mut scope = RequestScope::empty();
    assert!(matches!(
        fs.lookup(&cx, &mut scope, ROOT, OsStr::new(&retained_name)),
        Err(FfsError::NotFound(_))
    ));
    let survivor = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("ordinary"))
        .unwrap();
    assert_eq!(survivor.perm, 0o644);
    assert_eq!(
        fs.read(&cx, &mut scope, survivor.ino, 0, 32).unwrap(),
        b"ordinary data"
    );
    assert_eq!(
        fs.write(&cx, &mut scope, survivor.ino, 0, b"updated")
            .unwrap(),
        7
    );
    drop(fs);
    let reopened = engine_for(&cx, &device);
    reopened.check_clean_consistency(&cx).unwrap();
    assert_eq!(
        owned_files(&cx, &reopened),
        [] as [(NtfsReference, Vec<u16>); 0]
    );
    assert_eq!(
        native_stream(&cx, &reopened.volume_view(&cx).unwrap(), ordinary, ""),
        b"updatedy data"
    );
}

#[test]
fn ntfs_mount_utf8_name_length_refusal_preserves_retained_files() {
    // 128 UTF-16 code units are native-valid, but their 256 UTF-8 bytes exceed
    // the mounted name limit. Do not shorten or normalize the native name.
    assert_mount_name_refusal_preserves_orphans(&[0x00E9; 128], libc::ENAMETOOLONG);
}

#[test]
fn ntfs_mount_unpaired_utf16_refusal_preserves_retained_files() {
    assert_mount_name_refusal_preserves_orphans(&[0xD800], libc::EOPNOTSUPP);
}

#[test]
fn ntfs_mount_finishes_recovery_after_committed_cancellation() {
    for stage in [
        NtfsPersistenceStage::LogCommitBarrier,
        NtfsPersistenceStage::TargetMetadataBarrier,
        NtfsPersistenceStage::AckPublished,
    ] {
        let cx = Cx::for_testing();
        let device = synthetic_device();
        retain_files(&cx, &device, 1);
        let mut engine = engine_for(&cx, &device);
        let retained_name = String::from_utf16(&owned_files(&cx, &engine)[0].1).unwrap();
        let cancellation = cx.clone();
        engine.set_stage_hook(Some(Box::new(move |event| {
            if event.stage == stage {
                cancellation.set_cancel_requested(true);
            }
            Ok(())
        })));
        let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap_or_else(|error| {
            panic!("committed cleanup must finish admission at {stage:?}: {error}")
        });
        assert!(cx.checkpoint().is_err(), "cancellation remains requested");
        assert!(fs.last_durable_token().unwrap().is_some());

        let next = Cx::for_testing();
        let mut scope = RequestScope::empty();
        assert!(matches!(
            fs.lookup(&next, &mut scope, ROOT, OsStr::new(&retained_name)),
            Err(FfsError::NotFound(_))
        ));
        let created = fs
            .create(
                &next,
                &mut scope,
                ROOT,
                OsStr::new("after-recovery"),
                0o644,
                1000,
                1000,
            )
            .unwrap();
        assert_eq!(
            fs.write(&next, &mut scope, created.ino, 0, b"live")
                .unwrap(),
            4
        );
        assert_eq!(
            fs.read(&next, &mut scope, created.ino, 0, 16).unwrap(),
            b"live"
        );
        drop(fs);
        let reopened = engine_for(&next, &device);
        reopened.check_clean_consistency(&next).unwrap();
        assert_eq!(
            owned_files(&next, &reopened),
            [] as [(NtfsReference, Vec<u16>); 0]
        );
    }
}

#[test]
fn ntfs_orphan_open_handles_survive_and_writable_reopen_reaps() {
    for version in [NtfsFormatVersion::V3_0, NtfsFormatVersion::V3_1] {
        let cx = Cx::for_testing();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("orphan.img");
        let mut options = NtfsFormatOptions::new_image(path.clone(), 16);
        options.version = version;
        options.cluster_bytes = Some(4096);
        options.logfile_bytes = Some(256 * 1024);
        let report = format_image_file(&cx, &options, None).unwrap();
        assert!(report.boot_published && report.check_clean);
        let device = FaultInjectingNtfsDevice::new(std::fs::read(path).unwrap());
        let mut engine = engine_for(&cx, &device);
        let target = engine
            .create_file(&cx, "/", "open", &[0x61; 9000])
            .into_result()
            .unwrap()
            .0;
        engine
            .create_stream_at(
                &cx,
                target,
                &utf16("content"),
                b"stream",
                DEFAULT_NTFS_FILETIME,
            )
            .into_result()
            .unwrap();
        engine
            .create_file(&cx, "/", ".ffs-unlinked-user", b"keep user file")
            .into_result()
            .unwrap();
        let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
        let mut scope = RequestScope::empty();
        let base = fs
            .lookup(&cx, &mut scope, ROOT, OsStr::new("open"))
            .unwrap();
        let ads = fs
            .lookup(&cx, &mut scope, ROOT, OsStr::new("open:content"))
            .unwrap();
        let first = fs.open(&cx, &mut scope, base.ino, libc::O_RDWR).unwrap().0;
        let second = fs.open(&cx, &mut scope, base.ino, libc::O_RDWR).unwrap().0;
        let stream_handle = fs.open(&cx, &mut scope, ads.ino, libc::O_RDWR).unwrap().0;
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("open"))
            .unwrap();
        assert!(matches!(
            fs.lookup(&cx, &mut scope, ROOT, OsStr::new("open")),
            Err(FfsError::NotFound(_))
        ));
        assert_eq!(fs.getattr(&cx, &mut scope, base.ino).unwrap().nlink, 0);
        release(&fs, &cx, &mut scope, base.ino, first);
        fs.write(&cx, &mut scope, base.ino, 0, b"kept").unwrap();
        release(&fs, &cx, &mut scope, base.ino, second);
        fs.write(&cx, &mut scope, ads.ino, 0, b"alive!").unwrap();
        assert_eq!(fs.read(&cx, &mut scope, ads.ino, 0, 32).unwrap(), b"alive!");
        assert_eq!(fs.read(&cx, &mut scope, base.ino, 0, 4).unwrap(), b"kept");
        assert_eq!(
            fs.readdir(&cx, &mut scope, ROOT, 0)
                .unwrap()
                .iter()
                .filter(|entry| entry.name.starts_with(PREFIX.as_bytes()))
                .count(),
            1,
            "only the user's unrelated prefix name may be visible"
        );
        fs.fsync(&cx, &mut scope, ads.ino, 0, false).unwrap();
        let before = device.snapshot_durable_only();
        let free_before_close = fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free;
        release(&fs, &cx, &mut scope, ads.ino, stream_handle);
        assert!(fs.getattr(&cx, &mut scope, base.ino).is_err());
        assert!(fs.getattr(&cx, &mut scope, ads.ino).is_err());
        assert!(fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free >= free_before_close + 3);
        drop(fs);
        let closed = engine_for(&cx, &device);
        closed.check_clean_consistency(&cx).unwrap();
        assert_eq!(
            closed
                .volume_view(&cx)
                .unwrap()
                .check_allocations(&cx, AllocationLimits::default())
                .unwrap()
                .allocated_without_reference,
            Some(0),
            "final close must free DATA and catalog allocations without leaks"
        );
        assert_eq!(
            owned_files(&cx, &closed),
            [] as [(ffs_ondisk::ntfs::NtfsReference, Vec<u16>); 0]
        );
        drop(closed);

        // Reopen the earlier durable prefix as if the process died before its
        // final ADS close, losing all mount-local handle ownership.
        let crashed = FaultInjectingNtfsDevice::new(before.clone());
        let engine = engine_for(&cx, &crashed);
        engine.check_clean_consistency(&cx).unwrap();
        let retained = owned_files(&cx, &engine);
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].0, target);
        let retained_name = String::from_utf16(&retained[0].1).unwrap();
        let read_only = NtfsFs::new(&cx, engine.volume_view(&cx).unwrap(), 1000, 1000).unwrap();
        let visible = read_only
            .lookup(&cx, &mut scope, ROOT, OsStr::new(&retained_name))
            .unwrap();
        assert_eq!(
            read_only.read(&cx, &mut scope, visible.ino, 0, 4).unwrap(),
            b"kept"
        );
        read_only.flush_on_destroy(&cx).unwrap();
        drop(read_only);
        assert_eq!(crashed.write_bytes_total(), 0);
        assert_eq!(crashed.snapshot_live(), before);

        let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
        let cleanup_token = fs.last_durable_token().unwrap().unwrap();
        assert_eq!(
            cleanup_token.storage(),
            &fs.writable_storage_identity().unwrap().unwrap(),
            "writable admission must expose its native cleanup commit"
        );
        assert!(matches!(
            fs.lookup(&cx, &mut scope, ROOT, OsStr::new(&retained_name)),
            Err(FfsError::NotFound(_))
        ));
        let user = fs
            .lookup(&cx, &mut scope, ROOT, OsStr::new(".ffs-unlinked-user"))
            .unwrap();
        assert_eq!(
            fs.read(&cx, &mut scope, user.ino, 0, 64).unwrap(),
            b"keep user file"
        );
        drop(fs);
        let engine = engine_for(&cx, &crashed);
        engine.check_clean_consistency(&cx).unwrap();
        assert!(
            engine
                .volume_view(&cx)
                .unwrap()
                .record(&cx, target.record, Some(target.sequence))
                .is_err()
        );
        assert_eq!(
            owned_files(&cx, &engine),
            [] as [(ffs_ondisk::ntfs::NtfsReference, Vec<u16>); 0]
        );
        let after = crashed.snapshot_durable_only();
        let writes = crashed.write_bytes_total();
        let unchanged = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
        assert!(unchanged.last_durable_token().unwrap().is_none());
        drop(unchanged);
        assert_eq!(
            crashed.write_bytes_total(),
            writes,
            "second mount must not repeat cleanup"
        );
        assert_eq!(crashed.snapshot_durable_only(), after);
    }
}

#[test]
fn ntfs_orphan_retention_and_replacement_recover_at_native_barriers() {
    for (replace, pin_stream) in [(false, false), (false, true), (true, false), (true, true)] {
        let cx = Cx::for_testing();
        let device = synthetic_device();
        let mut engine = engine_for(&cx, &device);
        let victim = engine
            .create_file(&cx, "/", "victim", b"old payload")
            .into_result()
            .unwrap()
            .0;
        engine
            .create_stream_at(
                &cx,
                victim,
                &utf16("content"),
                b"old stream",
                DEFAULT_NTFS_FILETIME,
            )
            .into_result()
            .unwrap();
        let source = engine
            .create_file(&cx, "/", "source", b"new payload")
            .into_result()
            .unwrap()
            .0;
        let cuts = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&cuts);
        let backing = Arc::clone(&device);
        engine.set_stage_hook(Some(Box::new(move |event| {
            if matches!(
                event.stage,
                NtfsPersistenceStage::DirtyRestartBarrier
                    | NtfsPersistenceStage::LogCommitBarrier
                    | NtfsPersistenceStage::TargetMetadataBarrier
                    | NtfsPersistenceStage::AckPublished
            ) {
                captured
                    .lock()
                    .unwrap()
                    .push((event.stage, backing.snapshot_durable_only()));
            }
            Ok(())
        })));
        let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
        let mut scope = RequestScope::empty();
        let old = fs
            .lookup(&cx, &mut scope, ROOT, OsStr::new("victim"))
            .unwrap();
        let ads = fs
            .lookup(&cx, &mut scope, ROOT, OsStr::new("victim:content"))
            .unwrap();
        let pin = if pin_stream { ads.ino } else { old.ino };
        fs.open(&cx, &mut scope, pin, libc::O_RDWR).unwrap();
        if replace {
            fs.rename(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("source"),
                ROOT,
                OsStr::new("victim"),
            )
            .unwrap();
        } else {
            fs.unlink(&cx, &mut scope, ROOT, OsStr::new("victim"))
                .unwrap();
        }
        assert_eq!(
            fs.read(&cx, &mut scope, old.ino, 0, 64).unwrap(),
            b"old payload"
        );
        assert_eq!(
            fs.read(&cx, &mut scope, ads.ino, 0, 64).unwrap(),
            b"old stream"
        );
        assert_eq!(fs.getattr(&cx, &mut scope, old.ino).unwrap().nlink, 0);
        drop(fs);
        let cuts = std::mem::take(&mut *cuts.lock().unwrap());
        assert!(
            cuts.len() >= 4
                && [
                    NtfsPersistenceStage::DirtyRestartBarrier,
                    NtfsPersistenceStage::LogCommitBarrier,
                    NtfsPersistenceStage::TargetMetadataBarrier,
                    NtfsPersistenceStage::AckPublished,
                ]
                .iter()
                .all(|expected| cuts.iter().any(|(stage, _)| stage == expected)),
            "expected all 4 barrier stages in cuts, got {:?}",
            cuts.iter().map(|(s, _)| *s).collect::<Vec<_>>()
        );
        for (stage, image) in cuts {
            let committed = stage != NtfsPersistenceStage::DirtyRestartBarrier;
            let crashed = FaultInjectingNtfsDevice::new(image);
            let engine = engine_for(&cx, &crashed);
            engine.check_clean_consistency(&cx).unwrap();
            assert_eq!(
                owned_files(&cx, &engine).len(),
                usize::from(committed),
                "{stage:?}"
            );
            let volume = engine.volume_view(&cx).unwrap();
            assert_eq!(native_stream(&cx, &volume, victim, ""), b"old payload");
            assert_eq!(native_stream(&cx, &volume, source, ""), b"new payload");
            assert_eq!(
                native_stream(&cx, &volume, victim, "content"),
                b"old stream"
            );
            let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
            let destination = fs.lookup(&cx, &mut scope, ROOT, OsStr::new("victim"));
            if committed && !replace {
                assert!(matches!(destination, Err(FfsError::NotFound(_))));
            } else {
                let expected: &[u8] = if committed {
                    b"new payload"
                } else {
                    b"old payload"
                };
                assert_eq!(
                    fs.read(&cx, &mut scope, destination.unwrap().ino, 0, 64)
                        .unwrap(),
                    expected
                );
            }
            let source_path = fs.lookup(&cx, &mut scope, ROOT, OsStr::new("source"));
            assert_eq!(source_path.is_err(), committed && replace);
            drop(fs);
            let reopened = engine_for(&cx, &crashed);
            reopened.check_clean_consistency(&cx).unwrap();
            assert_eq!(
                owned_files(&cx, &reopened),
                [] as [(ffs_ondisk::ntfs::NtfsReference, Vec<u16>); 0]
            );
            let before = crashed.snapshot_durable_only();
            let writes = crashed.write_bytes_total();
            drop(NtfsFs::from_engine(&cx, reopened, 1000, 1000).unwrap());
            assert_eq!(crashed.write_bytes_total(), writes);
            assert_eq!(crashed.snapshot_durable_only(), before);
        }
    }
}

#[test]
fn ntfs_orphan_cleanup_recovers_at_native_barriers_and_sync_failures() {
    let cx = Cx::for_testing();
    let seed = synthetic_device();
    let target = retain_files(&cx, &seed, 1)[0];
    let retained_image = seed.snapshot_durable_only();
    let device = FaultInjectingNtfsDevice::new(retained_image.clone());
    let mut engine = engine_for(&cx, &device);
    let cuts = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&cuts);
    let backing = Arc::clone(&device);
    engine.set_stage_hook(Some(Box::new(move |event| {
        if matches!(
            event.stage,
            NtfsPersistenceStage::DirtyRestartBarrier
                | NtfsPersistenceStage::LogCommitBarrier
                | NtfsPersistenceStage::TargetMetadataBarrier
                | NtfsPersistenceStage::AckPublished
        ) {
            captured
                .lock()
                .unwrap()
                .push((event.stage, backing.snapshot_durable_only()));
        }
        Ok(())
    })));
    drop(NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap());
    let sync_count = device.state.lock().unwrap().sync_calls;
    let stage_cuts = std::mem::take(&mut *cuts.lock().unwrap());
    assert!(
        stage_cuts.len() >= 4
            && [
                NtfsPersistenceStage::DirtyRestartBarrier,
                NtfsPersistenceStage::LogCommitBarrier,
                NtfsPersistenceStage::TargetMetadataBarrier,
                NtfsPersistenceStage::AckPublished,
            ]
            .iter()
            .all(|expected| stage_cuts.iter().any(|(stage, _)| stage == expected)),
        "expected all 4 barrier stages in cleanup cuts, got {:?}",
        stage_cuts.iter().map(|(s, _)| *s).collect::<Vec<_>>()
    );
    let mut cuts: Vec<Vec<u8>> = stage_cuts.into_iter().map(|(_, image)| image).collect();
    assert!(sync_count > 0);
    for fail_at in 1..=sync_count {
        let device = FaultInjectingNtfsDevice::new(retained_image.clone());
        let engine = engine_for(&cx, &device);
        device.set_fail_sync_call(Some(fail_at));
        let _ = NtfsFs::from_engine(&cx, engine, 1000, 1000);
        cuts.push(device.snapshot_durable_only());
    }
    for image in cuts {
        let crashed = FaultInjectingNtfsDevice::new(image);
        drop(NtfsFs::from_engine(&cx, engine_for(&cx, &crashed), 1000, 1000).unwrap());
        let engine = engine_for(&cx, &crashed);
        engine.check_clean_consistency(&cx).unwrap();
        assert_eq!(
            owned_files(&cx, &engine),
            [] as [(ffs_ondisk::ntfs::NtfsReference, Vec<u16>); 0]
        );
        assert!(
            engine
                .volume_view(&cx)
                .unwrap()
                .record(&cx, target.record, Some(target.sequence))
                .is_err()
        );
        let before = crashed.snapshot_durable_only();
        let writes = crashed.write_bytes_total();
        drop(NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap());
        assert_eq!(crashed.write_bytes_total(), writes);
        assert_eq!(crashed.snapshot_durable_only(), before);
    }
}

#[test]
fn ntfs_orphan_recovery_validates_all_identities_before_any_delete() {
    let cx = Cx::for_testing();
    let seed = synthetic_device();
    retain_files(&cx, &seed, 2);
    let clean = seed.snapshot_durable_only();
    let inventory = owned_files(&cx, &engine_for(&cx, &seed));
    assert_eq!(inventory.len(), 2);
    let target = inventory[1].0;
    // Change magic, version, volume, boot identity, FILE record and sequence,
    // root record and sequence, exact name, then checksum. Recalculate a valid
    // checksum for every foreign identity: integrity alone is not ownership.
    for offset in [0, 16, 24, 32, 64, 70, 72, 78, 80, 112] {
        let device = FaultInjectingNtfsDevice::new(clean.clone());
        let mut engine = engine_for(&cx, &device);
        let mut marker = native_stream(&cx, &engine.volume_view(&cx).unwrap(), target, MARKER);
        marker[offset] ^= 1;
        if offset != 112 {
            let checksum = blake3::hash(&marker[..112]);
            marker[112..].copy_from_slice(checksum.as_bytes());
        }
        engine
            .write_stream_at(
                &cx,
                target,
                &utf16(MARKER),
                0,
                &marker,
                false,
                DEFAULT_NTFS_FILETIME,
            )
            .into_result()
            .unwrap();
        engine.check_clean_consistency(&cx).unwrap();
        let before = device.snapshot_durable_only();
        let writes = device.write_bytes_total();
        assert!(
            matches!(
                NtfsFs::from_engine(&cx, engine, 1000, 1000),
                Err(FfsError::Corruption { .. })
            ),
            "offset {offset}"
        );
        assert_eq!(
            device.write_bytes_total(),
            writes,
            "earlier valid orphan was consumed at offset {offset}"
        );
        assert_eq!(device.snapshot_live(), before);
        assert_eq!(device.snapshot_durable_only(), before);
    }
    for extra_link in [false, true] {
        let device = FaultInjectingNtfsDevice::new(clean.clone());
        let mut engine = engine_for(&cx, &device);
        if extra_link {
            let root = engine.resolve_path_reference(&cx, "/").unwrap();
            engine
                .link_at(&cx, target, root, &utf16("rescued-by-native-tool"))
                .into_result()
                .unwrap();
        } else {
            engine
                .write_stream_at(
                    &cx,
                    target,
                    &utf16(MARKER),
                    0,
                    &[0x5A; 5000],
                    false,
                    DEFAULT_NTFS_FILETIME,
                )
                .into_result()
                .unwrap();
        }
        engine.check_clean_consistency(&cx).unwrap();
        let before = device.snapshot_durable_only();
        let writes = device.write_bytes_total();
        assert!(matches!(
            NtfsFs::from_engine(&cx, engine, 1000, 1000),
            Err(FfsError::Corruption { .. })
        ));
        assert_eq!(device.write_bytes_total(), writes);
        assert_eq!(device.snapshot_live(), before);
        assert_eq!(device.snapshot_durable_only(), before);
    }
}

#[test]
fn ntfs_orphan_prefix_and_stream_collisions_are_preserved() {
    let cx = Cx::for_testing();
    let device = synthetic_device();
    let mut engine = engine_for(&cx, &device);
    let victim = engine
        .create_file(&cx, "/", "victim", b"original")
        .into_result()
        .unwrap()
        .0;
    engine
        .create_stream_at(
            &cx,
            victim,
            &utf16(MARKER),
            b"user-owned stream",
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    engine
        .create_file(&cx, "/", "source", b"replacement")
        .into_result()
        .unwrap();
    engine
        .create_file(&cx, "/", ".ffs-unlinked-collision", b"user-owned name")
        .into_result()
        .unwrap();
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    let before = device.snapshot_durable_only();
    let writes = device.write_bytes_total();
    assert!(matches!(
        engine.rename_entry_at(
            &cx,
            root,
            &utf16("source"),
            root,
            &utf16("victim"),
            false,
            Some(&utf16(".ffs-unlinked-collision")),
            DEFAULT_NTFS_FILETIME
        ),
        NtfsTxOutcome::NotCommitted(FfsError::Exists)
    ));
    assert_eq!(device.write_bytes_total(), writes);
    assert_eq!(device.snapshot_live(), before);
    let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
    assert_eq!(
        device.write_bytes_total(),
        writes,
        "legacy prefix-only names must remain untouched"
    );
    let mut scope = RequestScope::empty();
    let old = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("victim"))
        .unwrap();
    fs.open(&cx, &mut scope, old.ino, libc::O_RDWR).unwrap();
    assert!(matches!(
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("victim")),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert!(matches!(
        fs.rename(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("source"),
            ROOT,
            OsStr::new("victim")
        ),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(device.write_bytes_total(), writes);
    assert_eq!(device.snapshot_live(), before);
    assert_eq!(device.snapshot_durable_only(), before);
    assert_eq!(
        fs.read(&cx, &mut scope, old.ino, 0, 64).unwrap(),
        b"original"
    );
    drop(fs);
    let engine = engine_for(&cx, &device);
    assert_eq!(
        native_stream(&cx, &engine.volume_view(&cx).unwrap(), victim, MARKER),
        b"user-owned stream"
    );
    assert!(
        engine
            .resolve_path_reference(&cx, "/.ffs-unlinked-collision")
            .is_ok()
    );
}

#[test]
fn ntfs_orphan_marker_cannot_be_forged_through_fsops() {
    let cx = Cx::for_testing();
    let device = synthetic_device();
    let mut engine = engine_for(&cx, &device);
    let victim = engine
        .create_file(&cx, "/", "ordinary", b"payload")
        .into_result()
        .unwrap()
        .0;
    engine
        .create_stream_at(
            &cx,
            victim,
            &utf16(MARKER),
            b"preexisting user stream",
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    engine
        .create_stream_at(
            &cx,
            victim,
            &utf16("content"),
            b"other stream",
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    engine
        .create_file(&cx, "/", ".ffs-unlinked-user", b"preserve")
        .into_result()
        .unwrap();
    let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let stream = fs
        .lookup(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("ordinary:$FrankenFS.Orphan"),
        )
        .unwrap();
    assert_eq!(
        fs.read(&cx, &mut scope, stream.ino, 0, 64).unwrap(),
        b"preexisting user stream"
    );
    let before = device.snapshot_durable_only();
    let writes = device.write_bytes_total();
    for name in [
        ".ffs-unlinked-user:$FrankenFS.Orphan",
        ".ffs-unlinked-user:$frankenfs.orphan:$DATA",
    ] {
        assert!(matches!(
            fs.create(&cx, &mut scope, ROOT, OsStr::new(name), 0o666, 1000, 1000),
            Err(FfsError::PermissionDenied)
        ));
    }
    assert!(matches!(
        fs.open(&cx, &mut scope, stream.ino, libc::O_RDWR),
        Err(FfsError::PermissionDenied)
    ));
    assert!(matches!(
        fs.write(&cx, &mut scope, stream.ino, 0, b"forged intent"),
        Err(FfsError::PermissionDenied)
    ));
    assert!(matches!(
        fs.setattr(
            &cx,
            &mut scope,
            stream.ino,
            &SetAttrRequest {
                size: Some(0),
                ..SetAttrRequest::default()
            }
        ),
        Err(FfsError::PermissionDenied)
    ));
    assert!(matches!(
        fs.unlink(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("ordinary:$frankenfs.orphan")
        ),
        Err(FfsError::PermissionDenied)
    ));
    for (from, to) in [
        ("ordinary:content", "ordinary:$frankenfs.orphan"),
        ("ordinary:$FrankenFS.Orphan", "ordinary:renamed"),
    ] {
        assert!(matches!(
            fs.rename(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new(from),
                ROOT,
                OsStr::new(to)
            ),
            Err(FfsError::PermissionDenied)
        ));
    }
    assert_eq!(device.write_bytes_total(), writes);
    assert_eq!(device.snapshot_live(), before);
    assert_eq!(device.snapshot_durable_only(), before);
}
