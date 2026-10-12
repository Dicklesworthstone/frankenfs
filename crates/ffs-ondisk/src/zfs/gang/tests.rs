use super::*;

fn encode(pointer: &BlockPointer, order: Endian) -> [u8; 128] {
    let mut raw = [0; 128];
    for (index, word) in pointer.words.iter().enumerate() {
        raw[index * 8..index * 8 + 8].copy_from_slice(&order.encode(*word));
    }
    raw
}

fn pointer(data: &[u8], offset: u64, order: Endian, kind: u8, birth: u64) -> BlockPointer {
    assert!(!data.is_empty() && data.len().is_multiple_of(512));
    let sectors = data.len() as u64 / 512;
    let mut words = [0; 16];
    words[0] = (7_u64 << 32) | sectors;
    words[1] = offset / 512;
    words[6] = (sectors - 1)
        | ((sectors - 1) << 16)
        | (2_u64 << 32)
        | (8_u64 << 40)
        | (u64::from(kind) << 48)
        | (u64::from(order == Endian::Little) << 63);
    words[10] = birth;
    words[12..16].copy_from_slice(&checksum(data, 8, order).unwrap());
    BlockPointer { words }
}

fn seal(raw: &mut [u8; HEADER_BYTES], parent: &BlockPointer) {
    let order = parent.payload_order();
    raw[CHECKSUM_MAGIC_OFFSET..CHECKSUM_OFFSET].copy_from_slice(&order.encode(ECK_MAGIC));
    // Spell out the native verifier independently of the new getter. The
    // committed goldens below also come from a separate OpenSSL C oracle.
    let verifier = [
        (parent.words[0] >> 32) & 0x00ff_ffff,
        (parent.words[1] & 0x7fff_ffff_ffff_ffff) * 512,
        if parent.words[9] == 0 {
            parent.words[10]
        } else {
            parent.words[9]
        },
        0,
    ];
    for (index, word) in verifier.iter().enumerate() {
        let at = CHECKSUM_OFFSET + index * 8;
        raw[at..at + 8].copy_from_slice(&order.encode(*word));
    }
    let digest = checksum(raw, 8, Endian::Big).unwrap();
    for (index, word) in digest.iter().enumerate() {
        let at = CHECKSUM_OFFSET + index * 8;
        raw[at..at + 8].copy_from_slice(&order.encode(*word));
    }
}

fn header(parent: &BlockPointer, children: &[BlockPointer]) -> [u8; HEADER_BYTES] {
    let mut raw = [0; HEADER_BYTES];
    for (index, child) in children.iter().enumerate() {
        let at = index * POINTER_BYTES;
        raw[at..at + POINTER_BYTES].copy_from_slice(&encode(child, parent.payload_order()));
    }
    seal(&mut raw, parent);
    raw
}

fn fixture(order: Endian, allocated: u64) -> (BlockPointer, Vec<BlockPointer>, Vec<u8>) {
    let first = vec![0x11; 512];
    let second = vec![0x22; 512];
    let mut children = vec![
        pointer(&first, 0x8000, order, 0, 5),
        pointer(&second, 0xa000, order, 0, 5),
    ];
    for child in &mut children {
        child.words[0] = (7_u64 << 32) | (allocated / 512);
    }
    let data = [first, second].concat();
    let mut parent = pointer(&data, 0x2000, order, 19, 7);
    parent.words[0] = (7_u64 << 32) | (3 * allocated / 512);
    parent.words[1] |= 1_u64 << 63;
    parent.words[2] = (7_u64 << 32) | (allocated / 512);
    parent.words[3] = (1_u64 << 63) | (0x4000 / 512);
    parent.words[9] = 5;
    (parent, children, data)
}

fn refuses(raw: &[u8], parent: &BlockPointer, allocations: &[u64], reason: &str) {
    let error = GangHeader::parse(raw, parent, allocations).unwrap_err();
    assert!(error.to_string().contains(reason), "{error}");
}

#[test]
fn header_digest_matches_independent_c_openssl_vectors_in_both_orders() {
    let vectors: [(Endian, [u64; 4]); 2] = [
        (
            Endian::Little,
            [
                0x1f81_bf9c_b5e8_983b,
                0xfb21_9260_7701_53a2,
                0x6ae6_3008_6643_bc49,
                0x12e1_12e6_be90_88b3,
            ],
        ),
        (
            Endian::Big,
            [
                0xcef4_7de4_bdc8_c5a2,
                0xcb86_bf2c_3f5e_0f7b,
                0x23a4_970f_651c_2de7,
                0x45df_ab74_49ac_054d,
            ],
        ),
    ];
    for (order, expected) in vectors {
        let (parent, children, _) = fixture(order, 512);
        let raw = header(&parent, &children);
        for (index, word) in expected.iter().enumerate() {
            assert_eq!(order.u64(&raw, CHECKSUM_OFFSET + index * 8).unwrap(), *word);
        }
        for container in [Endian::Little, Endian::Big] {
            let decoded = BlockPointer::parse(&encode(&parent, container), container).unwrap();
            let parsed = GangHeader::parse(&raw, &decoded, &[512; 2]).unwrap();
            assert_eq!(parsed.children(), children.as_slice());
            assert_eq!(decoded.physical_birth(), 5);
            assert_eq!(decoded.birth(), 7);
        }
    }
}

#[test]
fn extra_header_copy_does_not_invent_extra_data_allocations() {
    for allocated in [512, 4096, 65_536] {
        let (parent, children, _) = fixture(Endian::Little, allocated);
        let raw = header(&parent, &children);
        let parsed = GangHeader::parse(&raw, &parent, &[allocated; 2]).unwrap();
        assert_eq!(parsed.children().len(), 2);
        assert_eq!(parent.regular_dvas().unwrap()[1].allocated_bytes, allocated);
        assert!(GangHeader::parse(&raw, &parent, &[allocated * 2; 2]).is_err());
    }
}

#[test]
fn heterogeneous_header_only_replica_uses_its_own_allocation() {
    for order in [Endian::Little, Endian::Big] {
        let (mut parent, children, data) = fixture(order, 512);
        // The data and first header use an ashift=9 vdev. The second header
        // lives on an ashift=12 vdev and has no corresponding data copies.
        parent.words[2] = (8_u64 << 32) | 8;
        let raw = header(&parent, &children);
        let dvas = parent.gang_dvas(&[512, 4096]).unwrap();
        assert_eq!((dvas[0].vdev, dvas[0].allocated_bytes), (7, 1536));
        assert_eq!((dvas[1].vdev, dvas[1].allocated_bytes), (8, 4096));
        let parsed = GangHeader::parse(&raw, &parent, &[512, 4096]).unwrap();
        assert_eq!(parsed.children(), children.as_slice());
        assert_eq!(parent.decode(&data).unwrap(), data);
        refuses(&raw, &parent, &[512, 512], "aggregate allocation");
        refuses(&raw, &parent, &[512, 3584], "aggregate allocation");
        refuses(
            &raw,
            &parent,
            &[4096, 512],
            "invalid native gang-header allocation",
        );
    }
}

#[test]
fn heterogeneous_member_copies_accumulate_allocations_independently() {
    for order in [Endian::Little, Endian::Big] {
        let (mut parent, mut children, data) = fixture(order, 1024);
        // Each copy owns its own header plus two member allocations: three
        // 1KiB allocations on vdev 7 and three 4KiB allocations on vdev 8.
        parent.words[2] = (8_u64 << 32) | 0x18;
        for (child, offset) in children.iter_mut().zip([0x0001_0000_u64, 0x0001_2000]) {
            child.words[2] = (8_u64 << 32) | 8;
            child.words[3] = offset / 512;
        }
        let raw = header(&parent, &children);
        let dvas = parent.gang_dvas(&[1024, 4096]).unwrap();
        assert_eq!((dvas[0].vdev, dvas[0].allocated_bytes), (7, 3072));
        assert_eq!((dvas[1].vdev, dvas[1].allocated_bytes), (8, 12_288));
        let parsed = GangHeader::parse(&raw, &parent, &[1024, 4096]).unwrap();
        assert_eq!(parsed.children(), children.as_slice());
        assert_eq!(parent.decode(&data).unwrap(), data);
        // The total header allocation stays equal. Shifting it between copies
        // must still fail rather than treating ASIZE as one combined budget.
        refuses(&raw, &parent, &[512, 4608], "aggregate allocation");
        refuses(&raw, &parent, &[1024, 1024], "aggregate allocation");
        let mut misaccounted = parent.clone();
        misaccounted.words[0] += 1;
        misaccounted.words[2] -= 1;
        refuses(&raw, &misaccounted, &[1024, 4096], "aggregate allocation");
    }
}

#[test]
fn header_allocation_count_must_match_every_declared_copy() {
    let (mut parent, children, _) = fixture(Endian::Little, 512);
    let raw = header(&parent, &children);
    let invalid_counts: [&[u64]; 4] = [&[], &[512], &[512; 3], &[512; 4]];
    for allocations in invalid_counts {
        let error = parent.gang_dvas(allocations).unwrap_err();
        assert!(error.to_string().contains("allocation count"), "{error}");
        refuses(&raw, &parent, allocations, "allocation count");
    }
    // The API counts declared DVAs, not a fixed assumed replication factor.
    parent.words[2..4].fill(0);
    let parsed = GangHeader::parse(&raw, &parent, &[512]).unwrap();
    assert_eq!(parsed.children(), children.as_slice());
    refuses(&raw, &parent, &[512; 2], "allocation count");
}

#[test]
fn verifier_uses_first_dva_not_the_selected_replica_or_logical_birth() {
    let (parent, children, _) = fixture(Endian::Little, 512);
    let raw = header(&parent, &children);
    let mut other_replica = parent.clone();
    other_replica.words[3] += 8;
    GangHeader::parse(&raw, &other_replica, &[512; 2]).unwrap();
    let mut reused = parent.clone();
    reused.words[10] = 99;
    GangHeader::parse(&raw, &reused, &[512; 2]).unwrap();
    for (index, replacement) in [
        (0, parent.words[0] ^ (1_u64 << 32)),
        (1, parent.words[1] + 1),
        (9, 6),
        (9, 0),
    ] {
        let mut changed = parent.clone();
        changed.words[index] = replacement;
        refuses(&raw, &changed, &[512; 2], "identity verifier mismatch");
    }
}

#[test]
fn every_header_byte_is_protected_and_input_is_never_modified() {
    for order in [Endian::Little, Endian::Big] {
        let (parent, children, _) = fixture(order, 512);
        let raw = header(&parent, &children);
        let before = raw;
        GangHeader::parse(&raw, &parent, &[512; 2]).unwrap();
        assert_eq!(raw, before);
        for at in 0..HEADER_BYTES {
            let mut damaged = raw;
            damaged[at] ^= 1;
            assert!(
                GangHeader::parse(&damaged, &parent, &[512; 2]).is_err(),
                "byte {at}"
            );
        }
    }
}

#[test]
fn malformed_header_lengths_and_pointer_byte_order_fail() {
    let (parent, children, _) = fixture(Endian::Little, 512);
    let raw = header(&parent, &children);
    for length in 0..HEADER_BYTES {
        refuses(&raw[..length], &parent, &[512; 2], "exactly 512 bytes");
    }
    let mut oversized = raw.to_vec();
    oversized.push(0);
    refuses(&oversized, &parent, &[512; 2], "exactly 512 bytes");
    let mut wrong_order = parent;
    wrong_order.words[6] ^= 1_u64 << 63;
    refuses(&raw, &wrong_order, &[512; 2], "byte order mismatch");
}

#[test]
fn reserved_filler_is_rejected_even_with_a_valid_checksum() {
    let (parent, children, _) = fixture(Endian::Little, 512);
    let mut raw = header(&parent, &children);
    raw[FILLER_START] = 1;
    seal(&mut raw, &parent);
    refuses(&raw, &parent, &[512; 2], "reserved filler");
}

#[test]
fn child_slots_must_be_contiguous_and_cover_exactly_the_parent() {
    let (parent, children, _) = fixture(Endian::Little, 512);
    let mut gap = header(&parent, &children);
    gap.copy_within(128..256, 256);
    gap[128..256].fill(0);
    seal(&mut gap, &parent);
    refuses(&gap, &parent, &[512; 2], "noncontiguous");
    refuses(
        &header(&parent, &children[..1]),
        &parent,
        &[512; 2],
        "partition",
    );
    let raw = header(&parent, &children);
    for sectors in [1_u64, 3] {
        let mut wrong_size = parent.clone();
        wrong_size.words[6] =
            (wrong_size.words[6] & !0xffff_ffff) | (sectors - 1) | ((sectors - 1) << 16);
        assert!(GangHeader::parse(&raw, &wrong_size, &[512; 2]).is_err());
    }
}

#[test]
fn transformed_typed_or_future_children_are_not_logical_data() {
    let (parent, children, _) = fixture(Endian::Little, 512);
    for bits in [
        1_u64 << 39,
        1_u64 << 48,
        1_u64 << 56,
        1_u64 << 61,
        1_u64 << 62,
        1_u64 << 63,
        1_u64 << 32,
    ] {
        let mut invalid_children = children.clone();
        invalid_children[0].words[6] ^= bits;
        let raw = header(&parent, &invalid_children);
        refuses(&raw, &parent, &[512; 2], "gang-member properties");
    }
    for birth in [0, 6] {
        let mut invalid_children = children.clone();
        invalid_children[0].words[10] = birth;
        refuses(
            &header(&parent, &invalid_children),
            &parent,
            &[512; 2],
            "gang-member properties",
        );
    }
}

#[test]
fn holes_do_not_silently_supply_zeros_or_hide_nonzero_unused_slots() {
    let (parent, mut children, _) = fixture(Endian::Little, 512);
    children[0].words[..6].fill(0);
    refuses(
        &header(&parent, &children),
        &parent,
        &[512; 2],
        "gang-member properties",
    );
}

#[test]
fn mixed_gang_flags_and_excess_child_copies_fail() {
    let (parent, children, _) = fixture(Endian::Little, 512);
    let raw = header(&parent, &children);
    let mut mixed = parent.clone();
    mixed.words[3] &= !(1_u64 << 63);
    refuses(&raw, &mixed, &[512; 2], "DVA flags");
    let mut parent_one_copy = parent;
    parent_one_copy.words[2..4].fill(0);
    let mut invalid_children = children;
    invalid_children[0].words[2] = (7_u64 << 32) | 1;
    invalid_children[0].words[3] = 0xc000 / 512;
    refuses(
        &header(&parent_one_copy, &invalid_children),
        &parent_one_copy,
        &[512],
        "invalid copies",
    );
}

#[test]
fn forged_gang_flag_without_first_copy_tree_allocation_fails_before_io() {
    let (mut parent, _, _) = fixture(Endian::Little, 512);
    parent.words[0] = (7_u64 << 32) | 2;
    assert!(parent.gang_dvas(&[512; 2]).is_err());
    // The extra header-only copy remains valid when DVA zero owns the tree.
    parent.words[0] = (7_u64 << 32) | 3;
    assert_eq!(parent.gang_dvas(&[512; 2]).unwrap()[1].allocated_bytes, 512);
}

#[test]
fn aggregate_asize_is_validated_per_copy_not_as_a_contiguous_span() {
    let (parent, children, _) = fixture(Endian::Little, 512);
    let raw = header(&parent, &children);
    for slot in [0, 2] {
        let mut changed = parent.clone();
        changed.words[slot] += 1;
        refuses(&raw, &changed, &[512; 2], "aggregate allocation");
    }
    for invalid_allocation in [0, 1, 511, 513, u64::MAX] {
        assert!(GangHeader::parse(&raw, &parent, &[invalid_allocation; 2]).is_err());
        for allocations in [[invalid_allocation, 512], [512, invalid_allocation]] {
            refuses(
                &raw,
                &parent,
                &allocations,
                "invalid native gang-header allocation",
            );
        }
    }
}

#[test]
fn ordinary_physical_data_and_leader_checksums_are_independent_of_header_hashes() {
    let (parent, children, data) = fixture(Endian::Little, 512);
    let raw = header(&parent, &children);
    parent.verify_physical(&data).unwrap();
    assert_eq!(parent.decode(&data).unwrap(), data);
    assert!(parent.verify_physical(&raw).is_err());
    let mut corrupt_data = data;
    corrupt_data[700] ^= 1;
    assert!(parent.verify_physical(&corrupt_data).is_err());
    assert!(parent.decode(&corrupt_data).is_err());
    // The independent header checksum remains valid despite that data error.
    GangHeader::parse(&raw, &parent, &[512; 2]).unwrap();
}
