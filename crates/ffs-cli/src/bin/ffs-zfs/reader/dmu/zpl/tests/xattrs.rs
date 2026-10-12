//! Constructed native graphs exercise both xattr storage forms through checked
//! DMU reads. These fixtures do not claim native OpenZFS pool or kernel evidence.

use super::*;
use crate::filesystem::ZfsFs;
use ffs_core::{FsOps, RequestScope};
use ffs_types::InodeNumber;
use std::ffi::OsStr;

const DIRECTORY: u64 = DATA_OFFSET + 0x40000;
const VALUES: u64 = DATA_OFFSET + 0x100000;
const BINARY: u64 = VALUES + 5 * 0x10000;

fn nvlist(fields: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    for (name, value) in fields {
        let mut pair = vec![0; 8];
        pair.extend_from_slice(&(name.len() as u32).to_be_bytes());
        pair.extend_from_slice(name.as_bytes());
        pair.resize(pair.len().next_multiple_of(4), 0);
        pair.extend_from_slice(&10_u32.to_be_bytes());
        pair.extend_from_slice(&(value.len() as u32).to_be_bytes());
        pair.extend_from_slice(value);
        pair.resize(pair.len().next_multiple_of(4), 0);
        let encoded = pair.len() as u32;
        pair[..4].copy_from_slice(&encoded.to_be_bytes());
        let decoded = (16 + name.len() + 1).next_multiple_of(8)
            + value.len().next_multiple_of(8);
        pair[4..8].copy_from_slice(&(decoded as u32).to_be_bytes());
        out.extend_from_slice(&pair);
    }
    out.extend_from_slice(&[0; 8]);
    out
}

fn packed(layout: u16, fields: &[(u16, Vec<u8>)], order: Endian) -> Vec<u8> {
    let mut raw = sa_bytes(layout, &[], order);
    for (id, bytes) in fields {
        if *id == 61 {
            u16put(&mut raw, 6, bytes.len() as u16, order);
        }
        raw.extend_from_slice(bytes);
        raw.resize(raw.len().next_multiple_of(8), 0);
    }
    raw
}

pub(super) fn augment(
    table: &mut [u8],
    store: &mut impl FnMut(u64, &[u8]),
    order: Endian,
    sa: u8,
    case: u8,
) {
    let other = if order == Endian::Little { Endian::Big } else { Endian::Little };
    let directory = match case { 23 => 13, 24 => 1 << 48, _ => 11 };
    if sa == 0 {
        table[3 * 512 + 192 + 104..3 * 512 + 192 + 112]
            .copy_from_slice(&order.encode(directory));
    } else {
        let large = vec![0x9b; 8193];
        let mut values: Vec<(&str, &[u8])> = vec![
            ("user.prefer", &[0xa1, 0, 0xff]), ("priority", b"raw-sa"),
            ("binary", b"fallback"),
        ];
        if sa == 2 {
            values.extend([
                ("compat", b"raw-sa".as_slice()), ("user.only-sa", &large),
                ("user.sa-empty", &[]), ("trusted.secret", b"private"),
                ("user.user.secret", b"private"), ("user.a/b", b"slash"),
            ]);
        }
        let mut dxattr = nvlist(&values);
        if case == 18 {
            dxattr[36..40].copy_from_slice(&23_u32.to_be_bytes());
        }
        let mut fields = sa_fields(other);
        let mut spill_fields = if sa == 2 { sa_fields(order).split_off(5) } else { Vec::new() };
        let tail = if sa == 2 { &mut spill_fields } else { &mut fields };
        tail.push((9, if sa == 2 { order } else { other }.encode(directory).to_vec()));
        tail.push((61, dxattr));
        let bonus = packed(2, if sa == 2 { &fields[..5] } else { &fields }, other);
        let mut file = node(19, 512, 2, 2, &bonus, 44, order);
        file[64..192].copy_from_slice(&table[3 * 512 + 64..3 * 512 + 192]);
        file[24..32].copy_from_slice(&order.encode(5120));
        let arrays = if sa == 2 {
            let mut spill = packed(3, &spill_fields, order);
            spill.resize(spill.len().next_power_of_two().max(512), 0);
            file[7] |= 4;
            file[384..512].copy_from_slice(&bp(&spill, SPILL, 44, 0, 20, order, order));
            if case == 21 { spill[20] ^= 1; }
            store(SPILL, &spill);
            vec![fields[..5].iter().map(|(id, _)| *id).collect(),
                spill_fields.iter().map(|(id, _)| *id).collect()]
        } else {
            vec![fields.iter().map(|(id, _)| *id).collect()]
        };
        table[3 * 512..4 * 512].copy_from_slice(&file);
        let registry = micro(&[(b"ZPL_SYMLINK", 47 | (3 << 16)),
            (b"ZPL_DXATTR", 61 | (3 << 16))], order);
        store(SA_REGISTRY, &registry);
        table[9 * 512 + 64..9 * 512 + 192]
            .copy_from_slice(&bp(&registry, SA_REGISTRY, 46, 0, 20, order, order));
        let (header, leaf) = layouts(&arrays, other);
        store(SA_LAYOUTS, &header);
        store(SA_LAYOUTS + 512, &leaf);
        table[10 * 512 + 64..10 * 512 + 192]
            .copy_from_slice(&bp(&header, SA_LAYOUTS, 47, 0, 20, order, other));
        table[10 * 512 + 192..10 * 512 + 320]
            .copy_from_slice(&bp(&leaf, SA_LAYOUTS + 512, 47, 0, 20, order, other));
    }
    let large = (0..65_536).map(|value| (value % 251) as u8).collect::<Vec<_>>();
    let values: [(&[u8], &[u8]); 7] = [
        (b"user.prefer", b"directory"), (b"compat", b"raw-dir"),
        (b"user.empty", &[]), (b"security.capability", b"private"),
        (b"user.large", &large), (b"user.binary", &[0, 255, 65, 0]),
        (b"user.priority", b"prefixed-dir"),
    ];
    let mut entries = Vec::new();
    for (index, (name, bytes)) in values.iter().enumerate() {
        let number = 12 + index;
        let mut attrs = legacy(0o100_600,
            if case == 19 && index == 4 { 65_537 } else { bytes.len() as u64 },
            if case == 16 && index == 0 { 2 } else { 11 }, order);
        attrs[120..128].copy_from_slice(&order.encode(u64::from(case != 15 || index != 0)));
        if case == 25 && index == 0 {
            attrs[64..72].copy_from_slice(&order.encode(41));
        }
        let mut payload = bytes.to_vec();
        payload.resize(payload.len().next_power_of_two().max(512), 0);
        let mut dn = node(19, payload.len(), 1, 0, &attrs, 17, order);
        if !bytes.is_empty() {
            let at = VALUES + index as u64 * 0x10000;
            dn[64..192].copy_from_slice(&bp(&payload, at, 19, 0,
                if case == 26 && index == 5 { 41 } else { 20 }, order, other));
            if case == 20 && index == 5 { payload[2] ^= 1; }
            store(at, &payload);
        }
        table[number * 512..(number + 1) * 512].copy_from_slice(&dn);
        entries.push((name.to_vec(),
            ((if case == 17 && index == 0 { 4 } else { 8 }) << 60) | number as u64));
    }
    if case == 27 {
        entries[0].0 = b"user.\xff".to_vec();
    }
    if matches!(case, 30 | 31) {
        entries[0].0 = if case == 30 { b".".to_vec() } else { b"..".to_vec() };
    }
    if matches!(case, 28 | 29) {
        entries = (0..if case == 28 { 4097 } else { 1600 })
            .map(|index| (format!("user.{index:040}").into_bytes(), (8 << 60) | 12))
            .collect();
    }
    let mut map = vec![0; (64 + entries.len() * 64).next_power_of_two().max(512)];
    map[..8].copy_from_slice(&other.encode((1 << 63) + 3));
    for (index, (name, number)) in entries.iter().enumerate() {
        let at = 64 + index * 64;
        map[at..at + 8].copy_from_slice(&other.encode(*number));
        map[at + 14..at + 14 + name.len()].copy_from_slice(name);
    }
    let mut attrs = legacy(0o040_700, entries.len() as u64 + 2,
        if case == 14 { 4 } else { 3 }, order);
    attrs[120..128].copy_from_slice(&order.encode(u64::from(case != 13)));
    let mut dn = node(20, map.len(), 1, 0, &attrs, 17, order);
    dn[64..192].copy_from_slice(&bp(&map, DIRECTORY, 20, 0, 20, order, other));
    if case == 22 { map[64] ^= 1; }
    store(DIRECTORY, &map);
    table[11 * 512..12 * 512].copy_from_slice(&dn);
}

#[test]
fn native_user_xattrs_cover_directory_sa_bonus_and_spill_in_both_byte_orders() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for sa in 0..=2 {
            let reads: Reads = Arc::default();
            let (leaf, meta) = graph(order, sa, 12, Arc::clone(&reads), None);
            let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
            let names = view.listxattr(&cx, 3).unwrap();
            let mut expected = vec!["user.binary", "user.compat", "user.empty", "user.large",
                "user.prefer", "user.priority"];
            if sa == 2 { expected.extend(["user.a/b", "user.only-sa", "user.sa-empty"]); }
            expected.sort_unstable();
            assert_eq!(names, expected);
            assert!(!reads.lock().unwrap().iter().any(|(at, _)| *at == BASE as u64 + BINARY));
            assert_eq!(view.getxattr(&cx, 3, "user.binary").unwrap().unwrap(), [0, 255, 65, 0]);
            assert_eq!(view.getxattr(&cx, 3, "user.empty").unwrap(), Some(Vec::new()));
            assert_eq!(view.getxattr(&cx, 3, "user.missing").unwrap(), None);
            assert_eq!(view.getxattr(&cx, 3, "user.prefer").unwrap().unwrap(),
                if sa == 0 { b"directory".to_vec() } else { vec![0xa1, 0, 0xff] });
            assert_eq!(view.getxattr(&cx, 3, "user.compat").unwrap().unwrap(),
                if sa == 2 { b"raw-sa".to_vec() } else { b"raw-dir".to_vec() });
            assert_eq!(view.getxattr(&cx, 3, "user.priority").unwrap().unwrap(), b"prefixed-dir");
            assert_eq!(view.getxattr(&cx, 3, "user.large").unwrap().unwrap(),
                (0..65_536).map(|value| (value % 251) as u8).collect::<Vec<_>>());
            if sa == 2 {
                assert_eq!(view.getxattr(&cx, 3, "user.only-sa").unwrap().unwrap(), vec![0x9b; 8193]);
                assert_eq!(view.getxattr(&cx, 3, "user.sa-empty").unwrap(), Some(Vec::new()));
                assert_eq!(view.getxattr(&cx, 3, "user.a/b").unwrap().unwrap(), b"slash");
            }
            assert!(view.listxattr(&cx, 6).unwrap().is_empty());
            assert_eq!(view.getxattr(&cx, 6, "user.missing").unwrap(), None);
            for number in 11..=18 {
                assert!(view.stat(&cx, number).is_err());
                assert!(view.read(&cx, number, 0, 1).is_err());
                assert!(view.listxattr(&cx, number).is_err());
            }
            for name in ["security.capability", "trusted.secret", "system.posix_acl_access",
                "user.security.capability", "user.trusted.secret", "user.system.secret",
                "user.freebsd:secret", "user.user.secret", "user.", "user.a\0b"] {
                assert!(view.getxattr(&cx, 3, name).is_err(), "{name:?}");
            }
            assert!(reads.lock().unwrap().iter().all(|(at, count)|
                *at >= BASE as u64 && *at + *count as u64 <= (BASE + LENGTH) as u64));
        }
    }
}

#[test]
fn xattr_catalog_rejects_foreign_private_objects_malformed_sa_and_resource_overflow() {
    let cx = Cx::for_testing();
    for (sa, case) in [(0,13), (0,14), (0,15), (0,16), (0,17), (1,18), (2,18),
        (2,21), (0,22), (0,23), (0,24), (2,24), (0,25), (0,27), (0,28), (0,29),
        (0,30), (0,31)] {
        let (leaf, meta) = graph(Endian::Little, sa, case, Arc::default(), None);
        let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
        assert!(view.listxattr(&cx, 3).is_err(), "SA {sa}, case {case}");
        assert!(view.getxattr(&cx, 3, "user.binary").is_err(), "SA {sa}, case {case}");
    }
    for case in [19, 20, 26] {
        let (leaf, meta) = graph(Endian::Little, 0, case, Arc::default(), None);
        let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
        assert!(view.listxattr(&cx, 3).unwrap().contains(&"user.binary".into()));
        let name = if case == 19 { "user.large" } else { "user.binary" };
        assert!(view.getxattr(&cx, 3, name).is_err(), "value case {case}");
        assert_eq!(view.getxattr(&cx, 3, "user.empty").unwrap(), Some(Vec::new()));
    }
}

#[test]
fn corrupt_prefixed_value_cannot_fall_back_to_a_valid_compatibility_sa_value() {
    let cx = Cx::for_testing();
    for sa in 1..=2 {
        let (leaf, meta) = graph(Endian::Little, sa, 20, Arc::default(), None);
        let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
        let (object, _) = view.file(&cx, 3).unwrap();
        let attrs = view.sa_attributes(&cx, &object).unwrap().xattrs().unwrap();
        assert_eq!(attrs.inline["binary"], b"fallback");
        assert!(view.getxattr(&cx, 3, "user.binary").is_err());
        assert_eq!(view.getxattr(&cx, 3, "user.empty").unwrap(), Some(Vec::new()));
    }
}

#[test]
fn extraction_mount_preserves_xattrs_across_hardlinks_and_propagates_value_cancellation() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for sa in 0..=2 {
            let reads: Reads = Arc::default();
            let (leaf, meta) = graph(order, sa, 12, Arc::clone(&reads), Some(BASE as u64 + BINARY));
            let view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
            let fs = ZfsFs::new(&cx, view, 1000, 1000).unwrap();
            let mut scope = RequestScope::empty();
            let file = fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("file.bin")).unwrap();
            let alias = fs.lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("alias.bin")).unwrap();
            assert_eq!(file.ino, alias.ino);
            assert_eq!(fs.listxattr(&cx, file.ino).unwrap(), fs.listxattr(&cx, alias.ino).unwrap());
            assert_eq!(fs.getxattr(&cx, alias.ino, "user.priority").unwrap().unwrap(), b"prefixed-dir");
            assert!(matches!(fs.getxattr(&cx, file.ino, "user.binary"), Err(FfsError::Cancelled)));
            assert_eq!(reads.lock().unwrap().iter().filter(|(at, _)| *at == BASE as u64 + BINARY).count(), 1);
            assert!(fs.getxattr(&cx, InodeNumber(13), "user.binary").is_err());
        }
    }
}
