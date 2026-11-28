//! Public sparse mutation, cache publication, and cancellation behavior.

use super::{
    Arc, ByteDevice, CLUSTER_BYTES, Cx, FaultInjectingNtfsDevice, NtfsPersistenceStage,
    NtfsTransactionEngine, SECTOR_BYTES, build_clean_ntfs_image, write_options_clean,
};
use ffs_core::{FsOps, RequestScope, SeekWhence, SetAttrRequest};
use ffs_ntfs::NtfsFs;
use ffs_types::InodeNumber;
use std::ffi::OsStr;

const PUNCH_KEEP_SIZE: i32 = 0x03;
const ZERO_RANGE: i32 = 0x10;
const ZERO_KEEP_SIZE: i32 = 0x11;

struct Fixture {
    device: Arc<FaultInjectingNtfsDevice>,
    engine: NtfsTransactionEngine,
    data: Vec<u8>,
    ads: Vec<u8>,
}

fn fixture() -> Fixture {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(256, 50, 0x5350_4152_5345_1001);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    let data: Vec<_> = (1_u8..=255).cycle().take(5 * CLUSTER_BYTES + 41).collect();
    let ads = vec![0xB7; 4 * CLUSTER_BYTES + 19];
    let (file, _) = engine
        .create_file(&cx, "/", "data", &data)
        .into_result()
        .unwrap();
    engine
        .create_stream(&cx, file, &"audit".encode_utf16().collect::<Vec<_>>(), &ads)
        .into_result()
        .unwrap();
    engine
        .link_file(&cx, "/data", "/", "alias")
        .into_result()
        .unwrap();
    Fixture {
        device,
        engine,
        data,
        ads,
    }
}

fn lookup(fs: &NtfsFs, cx: &Cx, scope: &mut RequestScope, name: &str) -> InodeNumber {
    fs.lookup(cx, scope, InodeNumber(1), OsStr::new(name))
        .unwrap()
        .ino
}

fn read_all(
    fs: &NtfsFs,
    cx: &Cx,
    scope: &mut RequestScope,
    ino: InodeNumber,
    size: usize,
) -> Vec<u8> {
    fs.read(cx, scope, ino, 0, u32::try_from(size).unwrap())
        .unwrap()
}

fn assert_clean(device: &FaultInjectingNtfsDevice) {
    let cx = Cx::for_testing();
    let image = device.snapshot_durable_only();
    let length = image.len() as u64 - SECTOR_BYTES as u64;
    let reopened = NtfsTransactionEngine::from_device(
        &cx,
        FaultInjectingNtfsDevice::new(image) as Arc<dyn ByteDevice>,
        0,
        length,
        write_options_clean(),
    )
    .unwrap();
    reopened.check_clean_consistency(&cx).unwrap();
}

#[test]
fn fallocate_publishes_sparse_data_mappings_and_allocation_for_links_and_ads() {
    let cx = Cx::for_testing();
    let fixture = fixture();
    let fs = NtfsFs::from_engine(&cx, fixture.engine, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let file = lookup(&fs, &cx, &mut scope, "data");
    let alias = lookup(&fs, &cx, &mut scope, "alias");
    let ads = lookup(&fs, &cx, &mut scope, "data:audit");
    assert_eq!(file, alias);
    assert_eq!(
        read_all(&fs, &cx, &mut scope, file, fixture.data.len()),
        fixture.data
    );
    assert_eq!(
        read_all(&fs, &cx, &mut scope, ads, fixture.ads.len()),
        fixture.ads
    );
    let before = fs.getattr(&cx, &mut scope, file).unwrap();
    let before_free = fs.statfs(&cx, &mut scope, file).unwrap().blocks_free;
    let cb = CLUSTER_BYTES as u64;
    fs.fallocate(&cx, &mut scope, alias, cb + 3, 2 * cb, PUNCH_KEEP_SIZE)
        .unwrap();
    let mut expected = fixture.data;
    expected[CLUSTER_BYTES + 3..3 * CLUSTER_BYTES + 3].fill(0);
    assert_eq!(
        read_all(&fs, &cx, &mut scope, file, expected.len()),
        expected
    );
    assert_eq!(
        read_all(&fs, &cx, &mut scope, alias, expected.len()),
        expected
    );
    let after = fs.getattr(&cx, &mut scope, file).unwrap();
    assert_eq!(
        (after.size, after.nlink, after.generation),
        (before.size, 2, before.generation)
    );
    assert_eq!(after.blocks, before.blocks - cb / 512);
    assert!(after.mtime >= before.mtime && after.ctime >= before.ctime);
    assert_eq!(
        fs.statfs(&cx, &mut scope, file).unwrap().blocks_free,
        before_free + 1
    );
    assert_eq!(
        fs.lseek(&cx, &mut scope, file, 0, SeekWhence::Hole)
            .unwrap(),
        2 * cb
    );
    assert_eq!(
        fs.lseek(&cx, &mut scope, file, 2 * cb, SeekWhence::Data)
            .unwrap(),
        3 * cb
    );
    let extents = fs.fiemap(&cx, &mut scope, file, 0, u64::MAX).unwrap();
    assert_ne!(extents, [] as [ffs_core::FiemapExtent; 0]);
    assert!(
        extents
            .iter()
            .all(|extent| { extent.logical >= 3 * cb || extent.logical + extent.length <= 2 * cb })
    );
    assert_eq!(
        read_all(&fs, &cx, &mut scope, ads, fixture.ads.len()),
        fixture.ads
    );

    let ads_before = fs.getattr(&cx, &mut scope, ads).unwrap();
    fs.fallocate(&cx, &mut scope, ads, cb, cb, PUNCH_KEEP_SIZE)
        .unwrap();
    let mut expected_ads = fixture.ads;
    expected_ads[CLUSTER_BYTES..2 * CLUSTER_BYTES].fill(0);
    assert_eq!(
        read_all(&fs, &cx, &mut scope, ads, expected_ads.len()),
        expected_ads
    );
    assert_eq!(
        read_all(&fs, &cx, &mut scope, file, expected.len()),
        expected
    );
    assert_eq!(
        fs.getattr(&cx, &mut scope, file).unwrap().blocks,
        after.blocks
    );
    let ads_after = fs.getattr(&cx, &mut scope, ads).unwrap();
    assert_eq!(ads_after.size, ads_before.size);
    assert_eq!(ads_after.blocks, ads_before.blocks - cb / 512);
    assert!(fs.last_durable_token().unwrap().is_some());
    assert_clean(&fixture.device);
}

#[test]
fn fallocate_refuses_bad_modes_ranges_and_read_only_targets_without_writes() {
    let cx = Cx::for_testing();
    let fixture = fixture();
    let read_only = NtfsFs::new(&cx, fixture.engine.volume_view(&cx).unwrap(), 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let file = lookup(&read_only, &cx, &mut scope, "data");
    let before = fixture.device.snapshot_durable_only();
    let writes = fixture.device.write_bytes_total();
    assert_eq!(
        read_only
            .fallocate(&cx, &mut scope, file, 0, 4096, PUNCH_KEEP_SIZE)
            .unwrap_err()
            .to_errno(),
        libc::EROFS
    );
    drop(read_only);
    let fs = NtfsFs::from_engine(&cx, fixture.engine, 1000, 1000).unwrap();
    let file = lookup(&fs, &cx, &mut scope, "data");
    for (offset, length, mode, errno) in [
        (0, 0, PUNCH_KEEP_SIZE, libc::EINVAL),
        (0, 4096, 0x02, libc::EINVAL),
        (0, 4096, 0, libc::EOPNOTSUPP),
        (0, 4096, 0x01, libc::EOPNOTSUPP),
        (0, 4096, 0x13, libc::EOPNOTSUPP),
        (0, 4096, 0x4000, libc::EOPNOTSUPP),
        (i64::MAX as u64, 1, PUNCH_KEEP_SIZE, libc::EFBIG),
        (u64::MAX, 1, PUNCH_KEEP_SIZE, libc::EFBIG),
    ] {
        assert_eq!(
            fs.fallocate(&cx, &mut scope, file, offset, length, mode)
                .unwrap_err()
                .to_errno(),
            errno
        );
    }
    assert_eq!(
        fs.fallocate(&cx, &mut scope, InodeNumber(1), 0, 4096, PUNCH_KEEP_SIZE)
            .unwrap_err()
            .to_errno(),
        libc::EISDIR
    );
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(
        fs.fallocate(&cancelled, &mut scope, file, 0, 4096, PUNCH_KEEP_SIZE)
            .is_err()
    );
    assert_eq!(fixture.device.write_bytes_total(), writes);
    assert_eq!(fixture.device.snapshot_live(), before);
    assert_eq!(fixture.device.snapshot_durable_only(), before);
    assert!(fs.last_durable_token().unwrap().is_none());

    fs.setattr(
        &cx,
        &mut scope,
        file,
        &SetAttrRequest {
            mode: Some(0o444),
            ..SetAttrRequest::default()
        },
    )
    .unwrap();
    let before = fixture.device.snapshot_durable_only();
    let writes = fixture.device.write_bytes_total();
    assert_eq!(
        fs.fallocate(&cx, &mut scope, file, 0, 4096, PUNCH_KEEP_SIZE)
            .unwrap_err()
            .to_errno(),
        libc::EACCES
    );
    assert_eq!(fixture.device.write_bytes_total(), writes);
    assert_eq!(fixture.device.snapshot_live(), before);
    assert_eq!(fixture.device.snapshot_durable_only(), before);
}

#[test]
fn fallocate_finishes_live_publication_after_committed_cancellation() {
    for stage in [
        NtfsPersistenceStage::LogCommitBarrier,
        NtfsPersistenceStage::TargetMetadataBarrier,
        NtfsPersistenceStage::AckPublished,
    ] {
        let cx = Cx::for_testing();
        let mut fixture = fixture();
        let cancelled = cx.clone();
        fixture.engine.set_stage_hook(Some(Box::new(move |event| {
            if event.stage == stage {
                cancelled.set_cancel_requested(true);
            }
            Ok(())
        })));
        let fs = NtfsFs::from_engine(&cx, fixture.engine, 1000, 1000).unwrap();
        let mut scope = RequestScope::empty();
        let file = lookup(&fs, &cx, &mut scope, "data");
        fs.fallocate(
            &cx,
            &mut scope,
            file,
            CLUSTER_BYTES as u64,
            CLUSTER_BYTES as u64,
            PUNCH_KEEP_SIZE,
        )
        .unwrap_or_else(|error| panic!("committed hole punch must publish at {stage:?}: {error}"));
        assert!(cx.checkpoint().is_err());
        assert!(fs.last_durable_token().unwrap().is_some());
        let next = Cx::for_testing();
        let mut expected = fixture.data;
        expected[CLUSTER_BYTES..2 * CLUSTER_BYTES].fill(0);
        assert_eq!(
            read_all(&fs, &next, &mut scope, file, expected.len()),
            expected
        );
        assert_eq!(
            fs.lseek(
                &next,
                &mut scope,
                file,
                CLUSTER_BYTES as u64,
                SeekWhence::Hole,
            )
            .unwrap(),
            CLUSTER_BYTES as u64
        );
        assert_eq!(
            fs.write(&next, &mut scope, file, CLUSTER_BYTES as u64 + 7, b"live",)
                .unwrap(),
            4
        );
        expected[CLUSTER_BYTES + 7..CLUSTER_BYTES + 11].copy_from_slice(b"live");
        assert_eq!(
            read_all(&fs, &next, &mut scope, file, expected.len()),
            expected
        );
        assert_clean(&fixture.device);
    }
}

#[test]
fn zero_range_fsops_fills_holes_preserves_aliases_and_allocates_keep_size_tail() {
    let cx = Cx::for_testing();
    let fixture = fixture();
    let fs = NtfsFs::from_engine(&cx, fixture.engine, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let file = lookup(&fs, &cx, &mut scope, "data");
    let alias = lookup(&fs, &cx, &mut scope, "alias");
    let ads = lookup(&fs, &cx, &mut scope, "data:audit");
    let cb = CLUSTER_BYTES as u64;
    assert_eq!(file, alias);
    fs.fallocate(&cx, &mut scope, file, cb, 2 * cb, PUNCH_KEEP_SIZE)
        .unwrap();
    let mut expected = fixture.data;
    expected[CLUSTER_BYTES..3 * CLUSTER_BYTES].fill(0);
    assert_eq!(
        read_all(&fs, &cx, &mut scope, alias, expected.len()),
        expected
    );
    let before = fs.getattr(&cx, &mut scope, file).unwrap();
    fs.fallocate(&cx, &mut scope, alias, cb + 3, 2 * cb, ZERO_RANGE)
        .unwrap();
    expected[CLUSTER_BYTES + 3..3 * CLUSTER_BYTES + 3].fill(0);
    assert_eq!(
        read_all(&fs, &cx, &mut scope, file, expected.len()),
        expected
    );
    let filled = fs.getattr(&cx, &mut scope, file).unwrap();
    assert_eq!(
        (filled.size, filled.nlink, filled.generation),
        (before.size, 2, before.generation)
    );
    assert_eq!(filled.blocks, before.blocks + 2 * cb / 512);
    assert_eq!(
        fs.lseek(&cx, &mut scope, alias, cb, SeekWhence::Hole)
            .unwrap(),
        filled.size
    );

    fs.fallocate(&cx, &mut scope, file, 8 * cb + 7, cb, ZERO_KEEP_SIZE)
        .unwrap();
    let retained = fs.getattr(&cx, &mut scope, alias).unwrap();
    assert_eq!(retained.size, filled.size);
    assert_eq!(retained.blocks, filled.blocks + 2 * cb / 512);
    assert_eq!(
        read_all(
            &fs,
            &cx,
            &mut scope,
            file,
            expected.len() + 3 * CLUSTER_BYTES
        ),
        expected
    );
    assert_eq!(
        read_all(&fs, &cx, &mut scope, ads, fixture.ads.len()),
        fixture.ads
    );

    // The named stream grows independently; the base file's size/allocation
    // stay unchanged while the common reader cache publishes the new bytes.
    fs.fallocate(&cx, &mut scope, ads, cb + 5, 5 * cb, ZERO_RANGE)
        .unwrap();
    let mut named = fixture.ads;
    named.resize(6 * CLUSTER_BYTES + 5, 0);
    named[CLUSTER_BYTES + 5..].fill(0);
    assert_eq!(read_all(&fs, &cx, &mut scope, ads, named.len()), named);
    let unchanged = fs.getattr(&cx, &mut scope, file).unwrap();
    assert_eq!(
        (unchanged.size, unchanged.blocks),
        (retained.size, retained.blocks)
    );
    assert!(fs.last_durable_token().unwrap().is_some());
    assert_clean(&fixture.device);
}

#[test]
fn zero_range_fsops_finishes_publication_after_committed_cancellation() {
    for stage in [
        NtfsPersistenceStage::LogCommitBarrier,
        NtfsPersistenceStage::TargetMetadataBarrier,
        NtfsPersistenceStage::AckPublished,
    ] {
        let cx = Cx::for_testing();
        let mut fixture = fixture();
        let cancelled = cx.clone();
        fixture.engine.set_stage_hook(Some(Box::new(move |event| {
            if event.stage == stage {
                cancelled.set_cancel_requested(true);
            }
            Ok(())
        })));
        let fs = NtfsFs::from_engine(&cx, fixture.engine, 1000, 1000).unwrap();
        let mut scope = RequestScope::empty();
        let file = lookup(&fs, &cx, &mut scope, "data");
        let old_size = fixture.data.len();
        fs.fallocate(
            &cx,
            &mut scope,
            file,
            7,
            7 * CLUSTER_BYTES as u64,
            ZERO_RANGE,
        )
        .unwrap_or_else(|error| panic!("committed zero range must publish at {stage:?}: {error}"));
        assert!(cx.checkpoint().is_err());
        assert!(fs.last_durable_token().unwrap().is_some());
        let next = Cx::for_testing();
        let mut expected = fixture.data;
        expected.resize(7 * CLUSTER_BYTES + 7, 0);
        expected[7..].fill(0);
        assert_eq!(
            read_all(&fs, &next, &mut scope, file, expected.len()),
            expected
        );
        assert_eq!(
            fs.getattr(&next, &mut scope, file).unwrap().size,
            expected.len() as u64
        );
        assert!(expected.len() > old_size);
        assert_clean(&fixture.device);
    }
}
