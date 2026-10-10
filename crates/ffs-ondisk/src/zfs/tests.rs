use super::*;

fn pointer(order: Endian, physical: &[u8], compression: u8, logical_bytes: usize) -> Vec<u8> {
    let mut words = [0_u64; 16];
    words[0] = physical.len() as u64 / 512;
    words[1] = 8;
    words[6] = (logical_bytes as u64 / 512 - 1)
        | ((physical.len() as u64 / 512 - 1) << 16)
        | (u64::from(compression) << 32)
        | (7 << 40)
        | (11 << 48)
        | (u64::from(order == Endian::Little) << 63);
    words[10] = 42;
    let sums = checksum(physical, 7, order).unwrap();
    words[12..].copy_from_slice(&sums);
    words
        .into_iter()
        .flat_map(|word| order.encode(word))
        .collect()
}
fn stamp(bytes: &mut [u8], offset: u64, order: Endian) {
    let tail = bytes.len() - 40;
    bytes[tail..tail + 8].copy_from_slice(&order.encode(ECK_MAGIC));
    bytes[tail + 8..].fill(0);
    bytes[tail + 8..tail + 16].copy_from_slice(&order.encode(offset));
    let sum = sha_words(bytes);
    for (i, word) in sum.into_iter().enumerate() {
        bytes[tail + 8 + i * 8..tail + 16 + i * 8].copy_from_slice(&order.encode(word));
    }
}

#[test]
fn checksum_vectors_are_native_words_not_host_endian_guesses() {
    assert_eq!(
        checksum(b"abc", 8, Endian::Little).unwrap(),
        [
            0xba78_16bf_8f01_cfea,
            0x4141_40de_5dae_2223,
            0xb003_61a3_9617_7a9c,
            0xb410_ff61_f200_15ad,
        ]
    );
    for order in [Endian::Little, Endian::Big] {
        let words: Vec<u8> = [1_u32, 2, 3, 4]
            .into_iter()
            .flat_map(|word| match order {
                Endian::Little => word.to_le_bytes(),
                Endian::Big => word.to_be_bytes(),
            })
            .collect();
        assert_eq!(checksum(&words, 7, order).unwrap(), [10, 20, 35, 56]);
        let words: Vec<u8> = [1_u64, 2, 3, 4]
            .into_iter()
            .flat_map(|word| order.encode(word))
            .collect();
        assert_eq!(checksum(&words, 6, order).unwrap(), [4, 6, 5, 8]);
        assert!(checksum(&[0; 3], 7, order).is_err());
        assert!(checksum(&[0; 8], 6, order).is_err());
        for unknown in [0, 1, 2, 3, 5, 9, 255] {
            assert!(checksum(&[0; 16], unknown, order).is_err());
        }
    }
}

#[test]
fn label_positions_and_uberblock_strides_are_checked() {
    let size = 64 * 1024 * 1024;
    assert_eq!(
        label_offsets(size + 123).unwrap(),
        [0, LABEL_BYTES, size - 2 * LABEL_BYTES, size - LABEL_BYTES]
    );
    assert!(label_offsets(DATA_OFFSET).is_err());
    assert_eq!(uberblock_bytes(9).unwrap(), 1024);
    assert_eq!(uberblock_bytes(12).unwrap(), 4096);
    assert_eq!(uberblock_bytes(16).unwrap(), 8192);
    for ashift in [0, 8, 17, 255] {
        assert!(uberblock_bytes(ashift).is_err());
    }
}

#[test]
fn salted_labels_reject_copy_to_another_offset_and_damage() {
    for order in [Endian::Little, Endian::Big] {
        let mut bytes = vec![0; 1024];
        bytes[..8].copy_from_slice(b"ZFS-test");
        stamp(&mut bytes, 131_072, order);
        // Independent SHA256 vectors from Python hashlib over the salted span.
        let expected = match order {
            Endian::Little => [
                0x99f7_a411_8251_bf2e,
                0x6b8e_599d_a5c4_d551,
                0xa458_6a32_cfe2_1ff2,
                0x31d4_118c_a9ee_96f9,
            ],
            Endian::Big => [
                0x918e_80f9_b050_99d9,
                0xc317_28b9_937e_93f5,
                0x6fdd_623a_7eec_a6f5,
                0xced5_c666_7a55_2402,
            ],
        };
        for (i, word) in expected.into_iter().enumerate() {
            assert_eq!(order.u64(&bytes, bytes.len() - 32 + i * 8).unwrap(), word);
        }
        let before = bytes.clone();
        assert_eq!(verify_label_checksum(&bytes, 131_072).unwrap(), order);
        assert!(verify_label_checksum(&bytes, 132_096).is_err());
        assert_eq!(bytes, before);
        bytes[71] ^= 1;
        assert!(verify_label_checksum(&bytes, 131_072).is_err());
        assert!(verify_label_checksum(&bytes[..39], 131_072).is_err());
    }
}

#[test]
fn regular_block_checks_bounds_checksum_and_codec_before_success() {
    for order in [Endian::Little, Endian::Big] {
        let data = vec![b'X'; 512];
        let raw = pointer(order, &data, 2, 512);
        let bp = BlockPointer::parse(&raw, order).unwrap();
        assert_eq!(bp.payload_order(), order);
        assert_eq!(bp.birth(), 42);
        assert_eq!(bp.decode(&data).unwrap(), data);
        let dva = bp.regular_dvas().unwrap()[0];
        assert_eq!(
            (dva.vdev, dva.offset, dva.allocated_bytes, dva.gang),
            (0, 4096, 512, false)
        );
        let mut damaged = data.clone();
        damaged[200] ^= 1;
        assert!(bp.decode(&damaged).is_err());
        assert!(bp.decode(&data[..511]).is_err());
        for cut in 0..128 {
            assert!(BlockPointer::parse(&raw[..cut], order).is_err());
        }
        for (word, value) in [(0, 1 << 24), (1, u64::MAX - 1), (7, 1), (10, 0)] {
            let mut bad = raw.clone();
            bad[word * 8..word * 8 + 8].copy_from_slice(&order.encode(value));
            assert!(
                BlockPointer::parse(&bad, order)
                    .unwrap()
                    .regular_dvas()
                    .is_err()
            );
        }
        for bit in [39, 61] {
            let mut bad = raw.clone();
            let prop = order.u64(&bad, 48).unwrap() | (1 << bit);
            bad[48..56].copy_from_slice(&order.encode(prop));
            assert!(
                BlockPointer::parse(&bad, order)
                    .unwrap()
                    .regular_dvas()
                    .is_err()
            );
        }
    }
}

#[test]
fn uberblock_root_identity_requires_a_checked_slot() {
    for order in [Endian::Little, Endian::Big] {
        let mut raw = vec![0; 4096];
        for (offset, value) in [
            (0, UBER_MAGIC),
            (8, 5000),
            (16, 43),
            (24, 123),
            (32, 1_700_000_000),
        ] {
            raw[offset..offset + 8].copy_from_slice(&order.encode(value));
        }
        raw[40..168].copy_from_slice(&pointer(order, &[0; 512], 2, 512));
        stamp(&mut raw, 131_072, order);
        let ub = Uberblock::parse(&raw, 131_072).unwrap();
        assert_eq!((ub.txg, ub.guid_sum, ub.root.birth()), (43, 123, 42));
        for (offset, value) in [(0, 0), (8, 4999), (16, 41)] {
            let mut bad = raw.clone();
            bad[offset..offset + 8].copy_from_slice(&order.encode(value));
            stamp(&mut bad, 131_072, order);
            assert!(Uberblock::parse(&bad, 131_072).is_err());
        }
        raw[101] ^= 1;
        assert!(Uberblock::parse(&raw, 131_072).is_err());
    }
}

#[test]
fn lzjb_literals_overlapping_matches_and_padding() {
    assert_eq!(decompress(b"\x00abcdefgh", 3, 8).unwrap(), b"abcdefgh");
    assert_eq!(
        decompress(&[8, b'a', b'b', b'c', 24, 3, 255, 255], 3, 12).unwrap(),
        b"abcabcabcabc"
    );
    for input in [
        vec![],
        vec![0],
        vec![1, 24],
        vec![1, 24, 3],
        vec![2, b'a', 0, 0],
    ] {
        assert!(decompress(&input, 3, 12).is_err());
    }
    assert!(decompress(&[8, b'a', b'b', b'c', 24, 3], 3, 11).is_err());
}

fn lz4(payload: &[u8]) -> Vec<u8> {
    let mut input = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    input.extend_from_slice(payload);
    input
}

#[test]
fn zfs_lz4_envelope_literals_matches_and_exact_output() {
    let packed = lz4(&[
        0x35, b'a', b'b', b'c', 3, 0, 0x50, b'X', b'Y', b'Z', b'1', b'2',
    ]);
    assert_eq!(decompress(&packed, 15, 17).unwrap(), b"abcabcabcabcXYZ12");
    let mut padded = packed.clone();
    padded.extend_from_slice(&[0xFF; 50]);
    assert_eq!(decompress(&padded, 15, 17).unwrap(), b"abcabcabcabcXYZ12");
    for size in [16, 18] {
        assert!(decompress(&packed, 15, size).is_err());
    }
    for payload in [
        vec![0],
        vec![0xF0, 255],
        vec![0, 0, 0],
        vec![0x10, b'A', 2, 0],
        vec![0x10],
    ] {
        assert!(decompress(&lz4(&payload), 15, 17).is_err());
    }
    assert!(decompress(&packed[..packed.len() - 1], 15, 17).is_err());
    assert!(decompress(&[255; 4], 15, 17).is_err());
    assert!(decompress(&packed, 16, 17).is_err());
    assert!(decompress(&packed, 15, MAX_BLOCK_BYTES + 1).is_err());
}

#[test]
fn compressed_block_verifies_padded_physical_bytes_before_decoding() {
    let mut physical = lz4(&[
        0x1F, b'A', 1, 0, 255, 255, 255, 234, 0x50, b'A', b'A', b'A', b'A', b'A',
    ]);
    physical.resize(512, 0);
    // One literal + (15+255+255+255+234+4) match + five literals = 1024.
    let raw = pointer(Endian::Little, &physical, 15, 1024);
    let bp = BlockPointer::parse(&raw, Endian::Little).unwrap();
    assert_eq!(bp.decode(&physical).unwrap(), vec![b'A'; 1024]);
    physical[511] = 1; // Allocated padding is inside the checksum boundary.
    assert!(bp.decode(&physical).is_err());
}
