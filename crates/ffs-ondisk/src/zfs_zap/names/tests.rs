use super::*;
use crate::zfs_zap::{FAT_TAG, FatHeader, LeafRoute};

fn w16(raw: &mut [u8], at: usize, value: u16, order: Endian) {
    let bytes = match order {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    raw[at..at + 2].copy_from_slice(&bytes);
}
fn w32(raw: &mut [u8], at: usize, value: u32, order: Endian) {
    let bytes = match order {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    raw[at..at + 4].copy_from_slice(&bytes);
}
fn w64(raw: &mut [u8], at: usize, value: u64, order: Endian) {
    raw[at..at + 8].copy_from_slice(&order.encode(value));
}
fn header(order: Endian, wide_hash: bool) -> Vec<u8> {
    let mut raw = vec![0; 512];
    for (at, word) in [(0, FAT_TAG), (8, 0x0002_f52a_b2ab), (56, 2), (64, 1),
        (72, 1), (80, 42), (88, 2), (96, u64::from(wide_hash)), (256, 1)] {
        w64(&mut raw, at, word, order);
    }
    raw
}
fn leaf(order: Endian, name: &[u8], hash: u64) -> Vec<u8> {
    assert!(name.len() < 42);
    let mut raw = vec![0; 512];
    w64(&mut raw, 0, 1_u64 << 63, order);
    w32(&mut raw, 24, 0x02ab_1eaf, order);
    w16(&mut raw, 30, 1, order);
    raw[48..80].fill(0xff);
    w16(&mut raw, 48 + (hash >> 60) as usize * 2, 0, order);
    let name_chunks = (name.len() + 1).div_ceil(21);
    let value_chunk = 1 + name_chunks;
    let free = value_chunk + 1;
    raw[80] = 252;
    raw[81] = 8;
    w16(&mut raw, 82, u16::MAX, order);
    w16(&mut raw, 84, 1, order);
    w16(&mut raw, 86, (name.len() + 1) as u16, order);
    w16(&mut raw, 88, value_chunk as u16, order);
    w16(&mut raw, 90, 1, order);
    w64(&mut raw, 96, hash, order);
    let mut terminated = name.to_vec();
    terminated.push(0);
    for (i, chunk) in terminated.chunks(21).enumerate() {
        let at = 80 + (i + 1) * 24;
        raw[at] = 251;
        raw[at + 1..at + 1 + chunk.len()].copy_from_slice(chunk);
        w16(&mut raw, at + 22,
            if i + 1 == name_chunks { u16::MAX } else { (i + 2) as u16 }, order);
    }
    let at = 80 + value_chunk * 24;
    raw[at] = 251;
    raw[at + 1..at + 9].copy_from_slice(&73_u64.to_be_bytes());
    w16(&mut raw, at + 22, u16::MAX, order);
    w16(&mut raw, 28, (18 - free) as u16, order);
    w16(&mut raw, 34, free as u16, order);
    for i in free..18 {
        raw[80 + i * 24] = 253;
        w16(&mut raw, 102 + i * 24, if i == 17 { u16::MAX } else { (i + 1) as u16 }, order);
    }
    raw
}

#[test]
fn normalized_hashes_preserve_spelling_and_validate_both_orders_and_hash_widths() {
    // Independent bitwise CRC64 vectors, salt 42; no parser-generated hashes.
    for order in [Endian::Little, Endian::Big] {
        for (wide, hash) in [(false, 0x041c_8790_0000_0000), (true, 0x041c_879b_3310_0000)] {
            let raw = header(order, wide);
            assert!(FatHeader::parse(&raw, order, 1).is_err());
            let parsed = FatHeader::parse_with_names(&raw, order, 1, NamePolicy::AsciiUppercase).unwrap();
            let route = parsed.routes(&parsed.embedded_table(&raw, order).unwrap(), 1).unwrap()[0];
            for name in [b"before".as_slice(), b"BEFORE", b"BeFoRe"] {
                let result = parsed.leaf(&leaf(order, name, hash), order, route).unwrap();
                assert_eq!(result[0].name, name);
                assert_eq!(result[0].scalar().unwrap(), 73);
            }
            // A self-consistent bucket and stored hash for UNNORMALIZED bytes
            // must fail, rather than authorizing a missing native lookup target.
            assert!(parsed.leaf(&leaf(order, b"before", 0x738b_4970_0000_0000), order, route).is_err());
            assert!(parsed.leaf(&leaf(order, b"caf\xc3\xa9", hash), order, route).is_err());
        }
    }
}

#[test]
fn normalized_long_names_keep_cross_chunk_hash_validation() {
    let order = Endian::Little;
    let parsed = FatHeader::parse_with_names(&header(order, false), order, 1, NamePolicy::AsciiUppercase).unwrap();
    let route = LeafRoute { block: 1, prefix: 0, prefix_bits: 0 };
    let raw = leaf(order, b"long_snapshot_name_crossing_chunks", 0x353a_6f70_0000_0000);
    assert_eq!(parsed.leaf(&raw, order, route).unwrap()[0].name, b"long_snapshot_name_crossing_chunks");
    let mut corrupt = raw;
    corrupt[80 + 24 + 1] = b'x';
    assert!(parsed.leaf(&corrupt, order, route).is_err());
}

#[test]
fn normalized_micro_maps_keep_exact_case_pairs_and_reject_incomplete_names() {
    for order in [Endian::Little, Endian::Big] {
        let mut raw = vec![0; 512];
        w64(&mut raw, 0, MICRO_TAG, order);
        w64(&mut raw, 16, 2, order);
        for (i, name) in [b"before", b"BEFORE"].into_iter().enumerate() {
            let at = 64 + i * 64;
            w64(&mut raw, at, 40 + i as u64, order);
            w32(&mut raw, at + 8, i as u32, order);
            raw[at + 14..at + 20].copy_from_slice(name);
        }
        assert!(microzap(&raw, order).is_err());
        assert!(microzap_with_names(&raw, order, NamePolicy::Unnormalized).is_err());
        let entries = microzap_with_names(&raw, order, NamePolicy::AsciiUppercase).unwrap();
        assert_eq!((&entries[0].name, entries[0].value), (&b"before".to_vec(), 40));
        assert_eq!((&entries[1].name, entries[1].value), (&b"BEFORE".to_vec(), 41));
        let mut duplicate = raw.clone();
        duplicate[142..148].copy_from_slice(b"before");
        assert!(microzap_with_names(&duplicate, order, NamePolicy::AsciiUppercase).is_err());
        let mut unicode = raw.clone();
        unicode[142] = 0x80;
        assert!(microzap_with_names(&unicode, order, NamePolicy::AsciiUppercase).is_err());
        raw[142..192].fill(b'x');
        assert!(microzap_with_names(&raw, order, NamePolicy::AsciiUppercase).is_err());
    }
}

#[test]
fn new_name_policy_never_admits_other_normalizations_or_binary_keys() {
    for order in [Endian::Little, Endian::Big] {
        for flags in [1, 4, 0x10, 0x12, 0x50, u64::MAX] {
            let mut raw = header(order, false);
            w64(&mut raw, 88, flags, order);
            assert!(FatHeader::parse_with_names(&raw, order, 1, NamePolicy::AsciiUppercase).is_err());
            w64(&mut raw, 0, MICRO_TAG, order);
            w64(&mut raw, 16, flags, order);
            assert!(microzap_with_names(&raw, order, NamePolicy::AsciiUppercase).is_err());
        }
        let mut raw = header(order, false);
        w64(&mut raw, 96, 2, order);
        assert!(FatHeader::parse_with_names(&raw, order, 1, NamePolicy::AsciiUppercase).is_err());
        for end in 0..512 {
            assert!(microzap_with_names(&raw[..end], order, NamePolicy::AsciiUppercase).is_err());
        }
    }
}
