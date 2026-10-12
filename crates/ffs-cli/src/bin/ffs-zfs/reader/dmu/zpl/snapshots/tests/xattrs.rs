//! Constructed native snapshot graphs verify root-local xattr identity and
//! historical checked reads; not evidence from native pools or mounted FUSE.

use super::*;
use crate::filesystem::ZfsFs;
use ffs_core::{FsOps, RequestScope};
use ffs_types::InodeNumber;
use std::ffi::OsStr;

pub(super) fn augment(
    image: &mut Image,
    table: &mut [u8],
    at: u64,
    state: usize,
    birth: u64,
    order: Endian,
    case: u8,
) {
    w64(table, 3 * 512 + 192 + 104, 6, order);
    let raw = micro(&[(b"user.version", (8 << 60) | 7)], 0, order);
    let mut attrs = metadata(4, 3, None, order);
    w64(
        &mut attrs,
        88,
        if case == 26 && state == 0 { 4 } else { 3 },
        order,
    );
    w64(&mut attrs, 120, 1, order);
    let mut dn = bonus(node(20, 512, 1, 0, order), 17, &attrs, order);
    dn[64..192].copy_from_slice(&pointer(&raw, at + 0x7000, 20, 0, birth - 4, order, order));
    image.store(at + 0x7000, &raw);
    table[6 * 512..7 * 512].copy_from_slice(&dn);

    let bytes = [b"\0before\xff".as_slice(), b"after\0", b"live\xfe"][state];
    let mut attrs = metadata(8, bytes.len() as u64, None, order);
    w64(&mut attrs, 88, 6, order);
    w64(&mut attrs, 120, 1, order);
    let mut dn = bonus(node(19, 512, 1, 0, order), 17, &attrs, order);
    let mut raw = vec![0; 512];
    raw[..bytes.len()].copy_from_slice(bytes);
    dn[64..192].copy_from_slice(&pointer(
        &raw,
        at + 0x7200,
        19,
        0,
        if case == 24 && state == 0 {
            21
        } else {
            birth - 4
        },
        order,
        order,
    ));
    if case == 25 && state == 0 {
        raw[1] ^= 1;
    }
    image.store(at + 0x7200, &raw);
    table[7 * 512..8 * 512].copy_from_slice(&dn);
}

#[test]
fn native_xattrs_follow_named_snapshot_roots_and_remain_isolated_in_extraction_mounts() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let (leaf, meta) = Image::new(order, 23).open(Arc::default(), None);
        let mut selected = pool(&leaf, meta);
        let mut live = selected.zpl(&cx, &[]).unwrap();
        let mut before = selected.zpl_snapshot(&cx, &[], b"before").unwrap();
        let mut after = selected.zpl_snapshot(&cx, &[], b"after").unwrap();
        for _ in 0..3 {
            assert_eq!(
                live.getxattr(&cx, 3, "user.version").unwrap().unwrap(),
                b"live\xfe"
            );
            assert_eq!(
                before.getxattr(&cx, 3, "user.version").unwrap().unwrap(),
                b"\0before\xff"
            );
            assert_eq!(
                after.getxattr(&cx, 3, "user.version").unwrap().unwrap(),
                b"after\0"
            );
            for view in [&mut live, &mut before, &mut after] {
                assert_eq!(view.listxattr(&cx, 3).unwrap(), ["user.version"]);
                assert_eq!(view.getxattr(&cx, 3, "user.absent").unwrap(), None);
                assert!(view.stat(&cx, 6).is_err());
                assert!(view.read(&cx, 7, 0, 1).is_err());
            }
        }
        let views = [live, before, after];
        for (view, expected) in
            views
                .into_iter()
                .zip([b"live\xfe".as_slice(), b"\0before\xff", b"after\0"])
        {
            let fs = ZfsFs::new(&cx, view, 1234, 5678).unwrap();
            let mut scope = RequestScope::empty();
            let file = fs
                .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("file"))
                .unwrap();
            assert_eq!(fs.listxattr(&cx, file.ino).unwrap(), ["user.version"]);
            assert_eq!(
                fs.getxattr(&cx, file.ino, "user.version").unwrap().unwrap(),
                expected
            );
        }
    }
}

#[test]
fn historical_xattr_corruption_and_younger_blocks_never_fall_back_to_the_head() {
    let cx = Cx::for_testing();
    for case in [24, 25, 26] {
        let (leaf, meta) = Image::new(Endian::Little, case).open(Arc::default(), None);
        let mut selected = pool(&leaf, meta);
        let mut before = selected.zpl_snapshot(&cx, &[], b"before").unwrap();
        assert!(
            before.getxattr(&cx, 3, "user.version").is_err(),
            "case {case}"
        );
        let mut live = selected.zpl(&cx, &[]).unwrap();
        assert_eq!(
            live.getxattr(&cx, 3, "user.version").unwrap().unwrap(),
            b"live\xfe"
        );
    }
    let failed_at = BASE as u64 + DATA_OFFSET + 0x37200;
    let reads: Reads = Arc::default();
    let (leaf, meta) = Image::new(Endian::Little, 23).open(Arc::clone(&reads), Some(failed_at));
    let mut selected = pool(&leaf, meta);
    let mut before = selected.zpl_snapshot(&cx, &[], b"before").unwrap();
    assert_eq!(before.listxattr(&cx, 3).unwrap(), ["user.version"]);
    assert!(matches!(
        before.getxattr(&cx, 3, "user.version"),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(
        reads
            .lock()
            .unwrap()
            .iter()
            .filter(|at| **at == failed_at)
            .count(),
        1
    );
    assert_eq!(
        selected
            .zpl(&cx, &[])
            .unwrap()
            .getxattr(&cx, 3, "user.version")
            .unwrap()
            .unwrap(),
        b"live\xfe"
    );
}
