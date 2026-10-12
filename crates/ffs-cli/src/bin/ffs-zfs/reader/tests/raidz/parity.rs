//! Constructed image integration, not native OpenZFS-pool interoperability.

use super::*;

#[test]
fn double_and_triple_parity_use_native_member_order_and_skip_parity_for_intact_data() {
    let cx = Cx::for_testing();
    for parity in 2..=3 {
        for width in [parity + 1, parity + 3, 8] {
            for (ashift, compressed) in [(9, false), (12, true), (16, false)] {
                for order in [Endian::Little, Endian::Big] {
                    let image =
                        StripedImage::root_with_parity(order, width, ashift, compressed, parity);
                    let expected = image.root.clone();
                    let map = image.map(ROOT).clone();
                    let locations = root_locations(&image);
                    let reads = image.reads();
                    let root = image
                        .open(&vec![Fault::None; width], true)
                        .root(&cx, 0, 2, 123)
                        .unwrap();
                    assert_eq!(root.data, expected);
                    let stripe = root.raidz.unwrap();
                    assert_eq!(stripe.allocated_bytes, map.allocated_bytes());
                    assert_eq!(
                        stripe.columns.iter().filter(|column| column.parity).count(),
                        parity
                    );
                    assert_eq!(stripe.reconstructed_children, [] as [usize; 0]);
                    assert!(!stripe.parity_read);
                    for &address in &locations[..parity] {
                        assert_eq!(count(&reads, address), 0);
                    }
                    for (actual, expected) in stripe.columns.iter().zip(map.columns()) {
                        assert_eq!(actual.child_id, expected.child_id);
                        assert_eq!(actual.member_guid, 1001 + expected.child_id as u64);
                        assert_eq!(actual.physical_offset, DATA_OFFSET + expected.offset);
                    }
                }
            }
        }
    }
}

#[test]
fn mixed_data_and_parity_faults_recover_through_the_actual_pool_reader() {
    let cx = Cx::for_testing();
    for parity in 2..=3 {
        let width = parity + 3;
        let mut cases = vec![vec![parity], vec![parity, parity + 1], vec![0, parity]];
        if parity == 3 {
            cases.extend([vec![3, 4, 5], vec![0, 1, 3], vec![0, 3, 4]]);
        }
        for order in [Endian::Little, Endian::Big] {
            for lost in &cases {
                for io in [false, true] {
                    let mut image = StripedImage::root_with_parity(order, width, 9, false, parity);
                    let expected = image.root.clone();
                    let children: Vec<_> = lost
                        .iter()
                        .filter(|&&index| index >= parity)
                        .map(|&index| image.column(ROOT, index).0)
                        .collect();
                    let mut faults = vec![Fault::None; width];
                    for &ordinal in lost {
                        let address = image.column(ROOT, ordinal);
                        if io {
                            faults[address.0] = Fault::Io(address.1);
                        } else {
                            image.poison(ROOT, ordinal, ordinal * 7);
                        }
                    }
                    let locations = root_locations(&image);
                    let reads = image.reads();
                    let root = image.open(&faults, true).root(&cx, 0, 2, 123).unwrap();
                    assert_eq!(
                        root.data, expected,
                        "parity={parity}, lost={lost:?}, io={io}"
                    );
                    let stripe = root.raidz.unwrap();
                    assert!(stripe.parity_read);
                    assert_eq!(stripe.reconstructed_children, children);
                    for address in locations {
                        assert_eq!(count(&reads, address), 1);
                    }
                }
            }
        }
    }
}

#[test]
fn parity_only_io_failure_does_not_make_good_data_unreadable() {
    let cx = Cx::for_testing();
    for parity in 2..=3 {
        let width = parity + 3;
        let image = StripedImage::root_with_parity(Endian::Little, width, 9, false, parity);
        let expected = image.root.clone();
        let mut faults = vec![Fault::None; width];
        let addresses: Vec<_> = (0..parity).map(|index| image.column(ROOT, index)).collect();
        for &address in &addresses {
            faults[address.0] = Fault::Io(address.1);
        }
        let reads = image.reads();
        let root = image.open(&faults, false).root(&cx, 0, 2, 123).unwrap();
        assert_eq!(root.data, expected);
        assert!(!root.raidz.unwrap().parity_read);
        assert_no_payload(&reads, &addresses);
    }
}

#[test]
fn beyond_parity_failure_can_try_another_declared_dva_but_never_return_bad_bytes() {
    let cx = Cx::for_testing();
    for parity in 2..=3 {
        let width = parity + 3;
        for all_bad in [false, true] {
            let mut image = StripedImage::root_with_parity(Endian::Big, width, 9, false, parity);
            let copy = image.add_root_copy(0x30_0000);
            let expected = image.root.clone();
            let lost = if parity == 2 {
                vec![2, 3, 4]
            } else {
                vec![0, 3, 4, 5]
            };
            for ordinal in lost {
                image.poison(ROOT, ordinal, ordinal * 11);
                if all_bad {
                    image.poison(copy, ordinal, ordinal * 11);
                }
            }
            let result = image
                .open(&vec![Fault::None; width], true)
                .root(&cx, 0, 2, 123);
            if all_bad {
                assert!(result.is_err());
            } else {
                let root = result.unwrap();
                assert_eq!(root.data, expected);
                assert_eq!(root.copy_index, 1);
            }
        }
    }
}

#[test]
fn cancellation_of_data_or_any_parity_stops_before_recovery_and_later_dvas() {
    let cx = Cx::for_testing();
    for parity in 2..=3 {
        let width = parity + 3;
        for cancelled in [parity, 0, parity - 1] {
            let mut image = StripedImage::root_with_parity(Endian::Little, width, 9, false, parity);
            let copy = image.add_root_copy(0x30_0000);
            if cancelled < parity {
                image.poison(ROOT, parity, 0);
            }
            let address = image.column(ROOT, cancelled);
            let next: Vec<_> = image
                .map(copy)
                .columns()
                .iter()
                .enumerate()
                .filter(|(_, column)| column.bytes != 0)
                .map(|(index, _)| image.column(copy, index))
                .collect();
            let mut faults = vec![Fault::None; width];
            faults[address.0] = Fault::Cancel(address.1);
            let reads = image.reads();
            assert!(matches!(
                image.open(&faults, true).root(&cx, 0, 2, 123),
                Err(FfsError::Cancelled)
            ));
            assert_eq!(count(&reads, address), 1);
            assert_no_payload(&reads, &next);
        }
    }
}

#[test]
fn parity_identity_and_late_dva_corruption_are_refused_before_payload_io() {
    let cx = Cx::for_testing();
    for parity in 2..=3 {
        let width = parity + 3;
        for case in 0..5 {
            let mut image = StripedImage::root_with_parity(Endian::Little, width, 9, false, parity);
            let locations = root_locations(&image);
            match case {
                0 => {
                    tree(&mut image.configs[1])
                        .fields
                        .insert("nparity".into(), Value::Unsigned(1));
                }
                1 => {
                    for config in &mut image.configs {
                        tree(config)
                            .fields
                            .insert("nparity".into(), Value::Unsigned(4));
                    }
                }
                2 => {
                    for config in &mut image.configs {
                        tree(config)
                            .fields
                            .insert("raidz_expand_txgs".into(), Value::Unsigned(0));
                    }
                }
                3 => {
                    image.add_root_copy(0x30_0000);
                    image.uberblock[64..72]
                        .copy_from_slice(&image.order.encode(LENGTH as u64 * 10 / 512));
                }
                _ => {
                    let old = image.order.u64(&image.uberblock, 40).unwrap();
                    image.uberblock[40..48].copy_from_slice(&image.order.encode(old + 1));
                }
            }
            image.refresh_labels();
            let reads = image.reads();
            assert!(
                image
                    .open(&vec![Fault::None; width], true)
                    .root(&cx, 0, 2, 123)
                    .is_err()
            );
            assert_no_payload(&reads, &locations);
        }
    }
}
