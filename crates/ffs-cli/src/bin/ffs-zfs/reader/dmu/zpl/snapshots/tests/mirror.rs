//! Constructed historical mirror roots exercise the complete pool owner.

use super::*;
use crate::filesystem::ZfsFs;
use crate::reader::Pool;
use crate::reader::tests::mirror::{Fault, MIRROR_GUID, install_labels, native_config, open_bytes};
use ffs_core::{FsOps, RequestScope};
use ffs_types::InodeNumber;
use std::ffi::OsStr;

const POOL_ROOT: u64 = DATA_OFFSET + 0x60000;
const OLD_INDIRECT: u64 = DATA_OFFSET + 0x35000;
const OLD_FIRST: u64 = DATA_OFFSET + 0x36000;
const OLD_LAST: u64 = DATA_OFFSET + 0x36800;
const LIVE_FIRST: u64 = DATA_OFFSET + 0x56000;
type MemberReads = Arc<Mutex<Vec<(u64, usize)>>>;

fn mirror_pool(order: Endian, case: u8, faults: [Fault; 2]) -> (Pool, [MemberReads; 2]) {
    let mut image = Image::new(order, case);
    let mut meta = node(10, 16384, 1, 0, order);
    meta[64..192].copy_from_slice(&pointer(&image.table, MOS, 10, 0, 80, order, order));
    let mut root = vec![0; 1024];
    root[..512].copy_from_slice(&meta);
    w64(&mut root, 704, 1, order);
    image.bytes[BASE + POOL_ROOT as usize..BASE + POOL_ROOT as usize + root.len()]
        .copy_from_slice(&root);
    let guids = [1001, 1002];
    let mut uberblock = vec![0; 1024];
    for (at, value) in [
        (0, 0x00ba_b10c),
        (8, 5000),
        (16, 100),
        (24, 123 + MIRROR_GUID + guids[0] + guids[1]),
        (32, 1_700_000_000),
    ] {
        w64(&mut uberblock, at, value, order);
    }
    uberblock[40..168].copy_from_slice(&pointer(&root, POOL_ROOT, 11, 0, 90, order, order));
    let reads: [MemberReads; 2] = std::array::from_fn(|_| Arc::default());
    let damaged: [&[u64]; 2] = [
        &[POOL_ROOT, OLDER_ROOT, OLD_INDIRECT, OLD_FIRST],
        &[OLD_LAST, LIVE_FIRST],
    ];
    let mut members = Vec::new();
    for index in 0..2 {
        let mut bytes = image.bytes.clone();
        let config = native_config(
            guids[index],
            &guids,
            9,
            LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES,
            90,
        );
        install_labels(&mut bytes, BASE, LENGTH as u64, order, &config, &uberblock);
        for offset in damaged[index] {
            bytes[BASE + *offset as usize] ^= 1;
        }
        members.push(open_bytes(
            bytes,
            BASE,
            LENGTH as u64,
            Arc::clone(&reads[index]),
            faults[index],
        ));
    }
    (Pool::from_leaves(members).unwrap(), reads)
}

fn count(reads: &MemberReads, offset: u64) -> usize {
    reads
        .lock()
        .unwrap()
        .iter()
        .filter(|(at, _)| *at == BASE as u64 + offset)
        .count()
}

#[test]
fn mirrored_snapshot_mounts_keep_historical_bytes_and_names_separate_from_head() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for case in [0, 21] {
            let (source, reads) = mirror_pool(order, case, [Fault::None; 2]);
            let (live, before) = {
                let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
                let rows = objects.snapshots(&cx, &[]).unwrap();
                assert_eq!(rows.len(), 2);
                let live = ZfsFs::new(&cx, objects.zpl(&cx, &[]).unwrap(), 1000, 1000).unwrap();
                let before = ZfsFs::new(
                    &cx,
                    objects.zpl_snapshot(&cx, &[], b"before").unwrap(),
                    1000,
                    1000,
                )
                .unwrap();
                (live, before)
            };
            drop(source);
            let mut scope = RequestScope::empty();
            let root = InodeNumber(1);
            let head_file = live
                .lookup(&cx, &mut scope, root, OsStr::new("file"))
                .unwrap();
            let old_file = before
                .lookup(&cx, &mut scope, root, OsStr::new("file"))
                .unwrap();
            assert_eq!(
                (head_file.ino, old_file.ino),
                (InodeNumber(4), InodeNumber(4))
            );
            assert_eq!((head_file.size, old_file.size), (900, 2049));
            for _ in 0..3 {
                assert_eq!(
                    before.read(&cx, &mut scope, old_file.ino, 0, 4096).unwrap(),
                    old_bytes()
                );
                assert_eq!(
                    live.read(&cx, &mut scope, head_file.ino, 0, 8).unwrap(),
                    b"EEEEEEEE"
                );
                assert_eq!(
                    before
                        .read(&cx, &mut scope, old_file.ino, 510, 1029)
                        .unwrap(),
                    old_bytes()[510..1539]
                );
                assert!(
                    before
                        .lookup(&cx, &mut scope, root, OsStr::new("gone"))
                        .is_ok()
                );
                assert!(matches!(
                    live.lookup(&cx, &mut scope, root, OsStr::new("gone")),
                    Err(FfsError::NotFound(_))
                ));
            }
            for offset in [POOL_ROOT, OLDER_ROOT, OLD_INDIRECT] {
                assert!(count(&reads[0], offset) > 0);
                assert!(count(&reads[1], offset) > 0);
            }
            if case == 0 {
                assert_eq!(count(&reads[0], OLD_FIRST), 1);
                assert_eq!(count(&reads[1], OLD_FIRST), 1);
                assert_eq!(count(&reads[0], OLD_LAST), 1);
                assert_eq!(count(&reads[1], OLD_LAST), 0);
                assert_eq!(count(&reads[0], LIVE_FIRST), 1);
                assert_eq!(count(&reads[1], LIVE_FIRST), 0);
            } else {
                for reads in &reads {
                    for offset in [OLD_FIRST, OLD_LAST, LIVE_FIRST] {
                        assert_eq!(count(reads, offset), 0);
                    }
                }
            }
        }
    }
}

#[test]
fn cancellation_of_a_later_historical_block_cannot_select_another_member_or_head() {
    let cx = Cx::for_testing();
    let (source, reads) = mirror_pool(
        Endian::Little,
        0,
        [Fault::Cancel(BASE as u64 + OLD_LAST), Fault::None],
    );
    let mut pool = source.objects(&cx, 0, 2, 123).unwrap();
    let mut before = pool.zpl_snapshot(&cx, &[], b"before").unwrap();
    assert!(matches!(
        before.read(&cx, 3, 0, 2049),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(count(&reads[0], OLD_LAST), 1);
    assert_eq!(count(&reads[1], OLD_LAST), 0);
    assert!(
        before
            .objects
            .cache
            .iter()
            .filter(|(bp, _)| bp.object_type() == 19 && bp.level() == 0)
            .all(|(_, block)| block.bytes.as_slice() == [b'A'; 512])
    );
    assert_eq!(
        pool.zpl(&cx, &[]).unwrap().read(&cx, 3, 0, 8).unwrap(),
        b"EEEEEEEE"
    );
    assert_eq!(before.stat(&cx, 3).unwrap().0.size, 2049);
}

#[test]
fn scrub_rechecks_mirrored_snapshot_blocks_without_reading_the_head() {
    use crate::reader::dmu::scrub::ScrubLimits;

    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for case in [0, 21] {
            let (source, reads) = mirror_pool(order, case, [Fault::None; 2]);
            let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
            let mut before = objects.zpl_snapshot(&cx, &[], b"before").unwrap();
            drop(source);
            assert_eq!(before.read(&cx, 3, 0, 2049).unwrap(), old_bytes());
            let old_count = count(&reads[0], OLD_INDIRECT);
            let report = before.scrub(&cx, ScrubLimits::default()).unwrap();
            assert!(report.is_clean(), "{report:?}");
            assert_eq!(report.view_txg, before.view_txg());
            assert_eq!(report.root_birth, 18);
            assert_eq!(report.objects_examined, 5);
            assert_eq!(report.verified_blocks, 6);
            assert!(count(&reads[0], OLD_INDIRECT) > old_count);
            assert!(count(&reads[1], OLD_INDIRECT) > 0);
            assert_eq!(count(&reads[0], LIVE_FIRST), 0);
            assert_eq!(count(&reads[1], LIVE_FIRST), 0);
            if case == 21 {
                assert_eq!(count(&reads[0], OLD_FIRST), 0);
                assert_eq!(count(&reads[1], OLD_FIRST), 0);
            }
            // A separately selected live view must retain its own root/caches.
            let head = objects.zpl(&cx, &[]).unwrap();
            let live = head.scrub(&cx, ScrubLimits::default()).unwrap();
            assert!(live.is_clean(), "{live:?}");
            assert_eq!(live.root_birth, 60);
            assert_ne!(live.root_birth, report.root_birth);
        }
    }
}

#[test]
fn scrub_reports_all_copy_failure_instead_of_substituting_live_data() {
    use crate::reader::dmu::scrub::ScrubLimits;

    let cx = Cx::for_testing();
    let faults = [Fault::Io(BASE as u64 + OLD_LAST); 2];
    let (source, reads) = mirror_pool(Endian::Little, 0, faults);
    let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
    let before = objects.zpl_snapshot(&cx, &[], b"before").unwrap();
    let report = before.scrub(&cx, ScrubLimits::default()).unwrap();
    assert!(!report.is_clean());
    assert_eq!(report.errors, 1);
    assert_eq!(report.issues[0].object, 3);
    assert_eq!(report.issues[0].block, Some(2));
    assert_eq!(report.objects_examined, 5);
    for member in &reads {
        assert_eq!(count(member, OLD_LAST), 1);
        assert_eq!(count(member, LIVE_FIRST), 0);
    }
}

#[test]
fn scrub_snapshot_cancellation_is_terminal_before_mirror_fallback() {
    use crate::reader::dmu::scrub::ScrubLimits;

    let cx = Cx::for_testing();
    let (source, reads) = mirror_pool(
        Endian::Little,
        0,
        [Fault::Cancel(BASE as u64 + OLD_LAST), Fault::None],
    );
    let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
    let before = objects.zpl_snapshot(&cx, &[], b"before").unwrap();
    assert!(matches!(
        before.scrub(&cx, ScrubLimits::default()),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(count(&reads[0], OLD_LAST), 1);
    assert_eq!(count(&reads[1], OLD_LAST), 0);
    assert_eq!(count(&reads[0], LIVE_FIRST), 0);
}

#[test]
fn followed_links_keep_mirrored_snapshot_identity_after_owner_drop_and_head_reads() {
    use crate::reader::dmu::zpl::PathPolicy;

    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for case in [0, 21] {
            let (source, reads) = mirror_pool(order, case, [Fault::None; 2]);
            let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
            let mut head = objects.zpl(&cx, &[]).unwrap();
            let mut before = objects.zpl_snapshot(&cx, &[], b"before").unwrap();
            drop(objects);
            drop(source);
            let head_file = head.resolve_with(&cx, b"/link", PathPolicy::Follow).unwrap();
            assert_eq!(head.read(&cx, head_file, 0, 8).unwrap(), b"EEEEEEEE");
            let head_reads = [count(&reads[0], LIVE_FIRST), count(&reads[1], LIVE_FIRST)];
            for _ in 0..2 {
                let old_file = before.resolve_with(&cx, b"/./link", PathPolicy::Follow).unwrap();
                assert_eq!(old_file, 3);
                assert_eq!(before.read(&cx, old_file, 0, 4096).unwrap(), old_bytes());
                let link = before.resolve_with(&cx, b"/link", PathPolicy::NoFollowFinal).unwrap();
                assert_eq!(link, 4);
                assert_eq!(before.readlink(&cx, link).unwrap(), b"file");
                assert!(matches!(before.resolve_with(&cx, b"/link/", PathPolicy::Follow),
                    Err(FfsError::NotDirectory)));
                assert_eq!(before.view_txg(), 20);
                assert_eq!([count(&reads[0], LIVE_FIRST), count(&reads[1], LIVE_FIRST)], head_reads);
            }
            assert!(count(&reads[1], OLD_INDIRECT) > 0);
        }
    }
}

#[test]
fn followed_historical_file_errors_do_not_reopen_a_healthy_live_head() {
    use crate::reader::dmu::zpl::PathPolicy;

    let cx = Cx::for_testing();
    for faults in [
        [Fault::Io(BASE as u64 + OLD_LAST); 2],
        [Fault::Cancel(BASE as u64 + OLD_LAST), Fault::None],
    ] {
        let (source, reads) = mirror_pool(Endian::Little, 0, faults);
        let mut objects = source.objects(&cx, 0, 2, 123).unwrap();
        let mut before = objects.zpl_snapshot(&cx, &[], b"before").unwrap();
        let file = before.resolve_with(&cx, b"/link", PathPolicy::Follow).unwrap();
        let result = before.read(&cx, file, 0, 2049);
        if matches!(faults[0], Fault::Cancel(_)) {
            assert!(matches!(result, Err(FfsError::Cancelled)));
            assert_eq!(count(&reads[1], OLD_LAST), 0);
        } else {
            assert!(result.is_err());
            assert_eq!(count(&reads[1], OLD_LAST), 1);
        }
        assert_eq!(count(&reads[0], LIVE_FIRST), 0);
        assert_eq!(count(&reads[1], LIVE_FIRST), 0);
    }
}
