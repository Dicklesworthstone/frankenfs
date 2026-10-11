use super::*;

const SALT: u64 = 0x0123_4567_89ab_cdef;
const ALPHA: u64 = 0xb77a_1c20_0000_0000;
const BETA: u64 = 0x5e16_8060_0000_0000;
const LONG: &[u8] = b"a-long-zap-key-crossing-array-chunks";
const LONG_HASH: u64 = 0xa630_3420_0000_0000;
const START: usize = 80; // 48-byte header + 16 uint16 hash slots for 512 bytes.

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
fn header(order: Endian, external: bool, growth: bool) -> Vec<u8> {
    let mut raw = vec![0; 512];
    for (at, value) in [
        (0, FAT_TAG),
        (8, 0x0002_f52a_b2ab),
        (32, 5),
        (56, 2),
        (64, 1),
        (72, 1),
        (80, SALT),
    ] {
        w64(&mut raw, at, value, order);
    }
    for at in (256..512).step_by(8) {
        w64(&mut raw, at, 1, order);
    }
    if external {
        for (at, value) in [(16, 3), (24, 1), (32, 6), (56, 4)] {
            w64(&mut raw, at, value, order);
        }
    }
    if growth {
        for (at, value) in [(40, 4), (48, 1), (56, 6)] {
            w64(&mut raw, at, value, order);
        }
    }
    raw
}
fn allocate_array(raw: &mut [u8], bytes: &[u8], next: &mut u16, order: Endian) -> u16 {
    if bytes.is_empty() {
        return CHAIN_END;
    }
    let first = *next;
    let parts = bytes.chunks(21);
    let count = parts.len();
    for (i, bytes) in parts.enumerate() {
        let at = START + usize::from(*next) * 24;
        raw[at] = 251;
        raw[at + 1..at + 1 + bytes.len()].copy_from_slice(bytes);
        w16(
            raw,
            at + 22,
            if i + 1 == count { CHAIN_END } else { *next + 1 },
            order,
        );
        *next += 1;
    }
    first
}

/// Hashes below are independently fixed CRC64 vectors, not values generated
/// by the parser. The builder is a constructed layout, not native pool evidence.
fn leaf(order: Endian, prefix: u64, bits: u16, entries: &[(&[u8], u8, &[u8], u64)]) -> Vec<u8> {
    let mut raw = vec![0; 512];
    w64(&mut raw, 0, 1_u64 << 63, order);
    w64(&mut raw, 16, prefix, order);
    w32(&mut raw, 24, 0x02ab_1eaf, order);
    w16(&mut raw, 30, entries.len() as u16, order);
    w16(&mut raw, 32, bits, order);
    raw[48..START].fill(0xFF);
    let mut next = 0_u16;
    for (name, width, bytes, hash) in entries {
        let index = next;
        next += 1;
        let mut terminated = name.to_vec();
        terminated.push(0);
        let name_chunk = allocate_array(&mut raw, &terminated, &mut next, order);
        let value_chunk = allocate_array(&mut raw, bytes, &mut next, order);
        let at = START + usize::from(index) * 24;
        let slot = (hash >> (60 - bits)) as usize & 15;
        let old = u16_at(&raw, 48 + slot * 2, order).unwrap();
        raw[at] = 252;
        raw[at + 1] = *width;
        w16(&mut raw, at + 2, old, order);
        w16(&mut raw, at + 4, name_chunk, order);
        w16(&mut raw, at + 6, terminated.len() as u16, order);
        w16(&mut raw, at + 8, value_chunk, order);
        w16(
            &mut raw,
            at + 10,
            (bytes.len() / usize::from(*width)) as u16,
            order,
        );
        w64(&mut raw, at + 16, *hash, order);
        w16(&mut raw, 48 + slot * 2, index, order);
    }
    assert!(next <= 18);
    w16(&mut raw, 28, 18 - next, order);
    w16(
        &mut raw,
        34,
        if next == 18 { CHAIN_END } else { next },
        order,
    );
    for free in next..18 {
        let at = START + usize::from(free) * 24;
        raw[at] = 253;
        w16(
            &mut raw,
            at + 22,
            if free == 17 { CHAIN_END } else { free + 1 },
            order,
        );
    }
    raw
}
fn route() -> LeafRoute {
    LeafRoute {
        block: 1,
        prefix: 0,
        prefix_bits: 0,
    }
}

#[test]
fn fixed_native_hashes_and_uint64_value_byte_order() {
    assert_eq!(name_hash(b"alpha", SALT, 28), ALPHA);
    assert_eq!(name_hash(b"beta", SALT, 28), BETA);
    assert_eq!(name_hash(LONG, SALT, 28), LONG_HASH);
    assert_eq!(name_hash(b"root_dataset", SALT, 48), 0xea59_a24f_c893_0000);
    for order in [Endian::Little, Endian::Big] {
        let h = FatHeader::parse(&header(order, false, false), order, 1).unwrap();
        let raw = leaf(
            order,
            0,
            0,
            &[(b"alpha", 8, &[1, 2, 3, 4, 5, 6, 7, 8], ALPHA)],
        );
        let result = h.leaf(&raw, order, route()).unwrap();
        assert_eq!(result[0].name, b"alpha");
        assert_eq!(result[0].scalar().unwrap(), 0x0102_0304_0506_0708);
    }
}

#[test]
fn multi_chunk_names_arrays_widths_and_zero_element_values() {
    let mut h = header(Endian::Little, false, false);
    w64(&mut h, 72, 2, Endian::Little);
    let h = FatHeader::parse(&h, Endian::Little, 1).unwrap();
    for order in [Endian::Little, Endian::Big] {
        for width in [1_u8, 2, 4, 8] {
            let values: Vec<_> = (0_u8..32).collect();
            let raw = leaf(
                order,
                0,
                0,
                &[(LONG, width, &values, LONG_HASH), (b"beta", 1, &[], BETA)],
            );
            let result = h.leaf(&raw, order, route()).unwrap();
            let long = result.iter().find(|entry| entry.name == LONG).unwrap();
            assert_eq!(long.integer_bytes, width);
            assert_eq!(long.values.len(), 32 / usize::from(width));
            match width {
                1 => assert_eq!(long.values, (0_u64..32).collect::<Vec<_>>()),
                2 => assert_eq!(long.values[1], 0x0203),
                4 => assert_eq!(long.values[1], 0x0405_0607),
                8 => assert_eq!(long.values[1], 0x0809_0a0b_0c0d_0e0f),
                _ => unreachable!(),
            }
            assert!(long.scalar().is_err());
            let empty = result.iter().find(|entry| entry.name == b"beta").unwrap();
            assert_eq!(empty.values, [] as [u64; 0]);
            assert!(empty.scalar().is_err());
        }
    }
}

#[test]
fn embedded_and_external_tables_resolve_exact_leaf_prefix_ranges() {
    for order in [Endian::Little, Endian::Big] {
        let raw = header(order, false, false);
        let h = FatHeader::parse(&raw, order, 1).unwrap();
        assert_eq!(
            h.routes(&h.embedded_table(&raw, order).unwrap(), 1)
                .unwrap(),
            [route()]
        );
        let mut raw = header(order, true, false);
        w64(&mut raw, 64, 2, order);
        let h = FatHeader::parse(&raw, order, 3).unwrap();
        let mut table = vec![1; 64];
        table[32..].fill(2);
        let routes = h.routes(&table, 3).unwrap();
        assert_eq!(
            routes,
            [
                LeafRoute {
                    block: 1,
                    prefix: 0,
                    prefix_bits: 1
                },
                LeafRoute {
                    block: 2,
                    prefix: 1,
                    prefix_bits: 1
                }
            ]
        );
        assert_eq!(
            h.leaf(
                &leaf(order, 0, 1, &[(b"beta", 1, &[9], BETA)]),
                order,
                routes[0]
            )
            .unwrap()[0]
                .values,
            [9]
        );
        assert!(
            h.leaf(
                &leaf(order, 1, 1, &[(b"alpha", 1, &[8], ALPHA)]),
                order,
                routes[0]
            )
            .is_err()
        );
        table.swap(0, 63);
        assert!(h.routes(&table, 3).is_err());
    }
}

#[test]
fn growing_tables_keep_old_authority_and_check_completed_prefix() {
    for order in [Endian::Little, Endian::Big] {
        let h = FatHeader::parse(&header(order, true, true), order, 5).unwrap();
        assert_eq!(h.table_blocks(), 3..4);
        assert_eq!(h.copied_blocks(), 4..6);
        let table = vec![1; 64];
        let mut copied = vec![1; 64];
        h.check_copied_block(4, &copied, &table).unwrap();
        h.check_copied_block(5, &copied, &table).unwrap();
        copied[63] = 2;
        assert!(h.check_copied_block(5, &copied, &table).is_err());
        assert!(h.check_copied_block(6, &copied, &table).is_err());
        let mut partial = header(order, true, true);
        w64(&mut partial, 48, 0, order);
        // Reserved but not copied blocks can be beyond dn_maxblkid.
        assert!(FatHeader::parse(&partial, order, 3).is_ok());
        let mut alias = table;
        alias.fill(4);
        assert!(h.routes(&alias, 5).is_err());
    }
}

#[test]
fn malformed_headers_tables_and_budgets_are_refused() {
    let order = Endian::Little;
    let original = header(order, true, true);
    for (at, value) in [
        (0, 0),
        (8, 0),
        (16, 0),
        (24, 2),
        (32, 21),
        (40, 3),
        (48, 2),
        (56, 5),
        (64, 0),
        (64, 4097),
        (72, 65_537),
        (80, 0),
        (88, 1),
        (96, 2),
    ] {
        let mut bad = original.clone();
        w64(&mut bad, at, value, order);
        assert!(
            FatHeader::parse(&bad, order, 5).is_err(),
            "field {at}: {value}"
        );
    }
    for end in [0, 8, 103, 511] {
        assert!(FatHeader::parse(&original[..end], order, 5).is_err());
    }
    let h = FatHeader::parse(&original, order, 5).unwrap();
    for target in [0, 3, 4, 5, 6, u64::MAX] {
        assert!(h.routes(&vec![target; 64], 5).is_err());
    }
    assert!(h.routes(&[1; 63], 5).is_err());
}

#[test]
fn cycles_aliases_hash_damage_and_orphan_chunks_never_publish_entries() {
    let order = Endian::Little;
    let h = FatHeader::parse(&header(order, false, false), order, 1).unwrap();
    let original = leaf(order, 0, 0, &[(b"alpha", 8, &[0; 8], ALPHA)]);
    for (at, value) in [
        (START + 2, 0),
        (START + 4, 2),
        (START + 8, 1),
        (START + 6, 5),
        (START + 10, 4),
        (START + 24 + 22, 1),
        (START + 48 + 22, 0),
        (START + 72 + 22, 3),
        (28, 14),
        (30, 2),
        (34, 4),
    ] {
        let mut bad = original.clone();
        w16(&mut bad, at, value, order);
        assert!(h.leaf(&bad, order, route()).is_err(), "field {at}");
    }
    for at in [START + 1, START + 16, START + 24 + 1, START + 72, 24, 36] {
        let mut bad = original.clone();
        bad[at] ^= 0x80;
        assert!(h.leaf(&bad, order, route()).is_err(), "byte {at}");
    }
    let mut unlinked = original;
    w16(&mut unlinked, 48 + 11 * 2, CHAIN_END, order);
    assert!(h.leaf(&unlinked, order, route()).is_err());
}

#[test]
fn hash64_profile_retains_collision_identity_and_rejects_wrong_hash_width() {
    let order = Endian::Big;
    let mut raw = header(order, false, false);
    w64(&mut raw, 96, 1, order);
    let h = FatHeader::parse(&raw, order, 1).unwrap();
    let raw = leaf(
        order,
        0,
        0,
        &[(b"alpha", 8, &[0; 8], 0xb77a_1c2b_bad5_0000)],
    );
    assert_eq!(h.leaf(&raw, order, route()).unwrap()[0].collision, 0);
    let wrong = leaf(order, 0, 0, &[(b"alpha", 8, &[0; 8], ALPHA)]);
    assert!(h.leaf(&wrong, order, route()).is_err());
}
