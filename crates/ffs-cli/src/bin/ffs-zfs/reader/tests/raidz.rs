//! Constructed native RAIDZ admission and checksum-guided stripe reads.

pub(in crate::reader) mod fixture;
mod parity;

use super::*;
use crate::reader::tests::mirror::{Fault, repack};
use fixture::{ROOT, StripedImage, count};

fn root_locations(image: &StripedImage) -> Vec<(usize, u64)> {
    image
        .map(ROOT)
        .columns()
        .iter()
        .enumerate()
        .filter(|(_, column)| column.bytes != 0)
        .map(|(index, _)| image.column(ROOT, index))
        .collect()
}

fn assert_no_payload(reads: &[Reads], locations: &[(usize, u64)]) {
    for address in locations {
        assert_eq!(count(reads, *address), 0);
    }
}

#[test]
fn complete_raidz_groups_use_native_guids_and_return_original_psize_across_sector_sizes() {
    let cx = Cx::for_testing();
    for (width, ashift) in [(2, 9), (3, 9), (4, 12), (8, 16)] {
        for order in [Endian::Little, Endian::Big] {
            for compressed in [false, true] {
                let image = StripedImage::root(order, width, ashift, compressed);
                let expected = image.root.clone();
                let map = image.map(ROOT).clone();
                let parity = image.column(ROOT, 0);
                let logs = image.reads();
                let root = image
                    .open(&vec![Fault::None; width], true)
                    .root(&cx, 0, 2, 123)
                    .unwrap();
                assert_eq!(root.data, expected);
                assert_eq!(root.copy_index, 0);
                let stripe = root.raidz.unwrap();
                assert_eq!(stripe.dva_offset, ROOT - DATA_OFFSET);
                assert_eq!(stripe.allocated_bytes, map.allocated_bytes());
                assert!(!stripe.parity_read);
                assert!(stripe.reconstructed_children.is_empty());
                assert_eq!(count(&logs, parity), 0);
                for (actual, expected) in stripe.columns.iter().zip(map.columns()) {
                    assert_eq!(actual.child_id, expected.child_id);
                    assert_eq!(actual.member_guid, 1001 + expected.child_id as u64);
                    assert_eq!(actual.physical_offset, DATA_OFFSET + expected.offset);
                    assert_eq!(actual.bytes, expected.bytes);
                }
                assert!(stripe.columns[0].parity);
                assert!(stripe.columns[1..].iter().all(|column| !column.parity));
                for reads in &logs {
                    assert!(reads.lock().unwrap().iter().all(|(offset, bytes)| {
                        *offset >= BASE as u64 && *offset + *bytes as u64 <= (BASE + LENGTH) as u64
                    }));
                }
            }
        }
    }
}

#[test]
fn each_data_column_recovers_a_checksum_error_or_physical_io_erasure() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for width in [2, 3, 8] {
            let columns = StripedImage::root(order, width, 9, false)
                .map(ROOT)
                .columns()
                .len();
            for ordinal in 1..columns {
                for io in [false, true] {
                    let mut image = StripedImage::root(order, width, 9, false);
                    if image.map(ROOT).columns()[ordinal].data_offset.is_none() {
                        continue;
                    }
                    let data = image.column(ROOT, ordinal);
                    let parity = image.column(ROOT, 0);
                    let expected = image.root.clone();
                    let mut faults = vec![Fault::None; width];
                    if io {
                        faults[data.0] = Fault::Io(data.1);
                    } else {
                        image.poison(ROOT, ordinal, 0);
                    }
                    let reads = image.reads();
                    let root = image.open(&faults, true).root(&cx, 0, 2, 123).unwrap();
                    assert_eq!(root.data, expected);
                    let stripe = root.raidz.unwrap();
                    assert!(stripe.parity_read);
                    assert_eq!(stripe.reconstructed_children, vec![data.0]);
                    assert_eq!(count(&reads, data), 1);
                    assert_eq!(count(&reads, parity), 1);
                }
            }
        }
    }
}

#[test]
fn intact_data_needs_no_parity_and_checksum_excludes_ashift_padding() {
    let cx = Cx::for_testing();
    for padded in [false, true] {
        let mut image = StripedImage::root(Endian::Little, 4, 12, true);
        let parity = image.column(ROOT, 0);
        let expected = image.root.clone();
        let mut faults = vec![Fault::None; 4];
        faults[parity.0] = Fault::Io(parity.1);
        if padded {
            // The root's PSIZE is 512; native sector I/O is 4096. Bytes after
            // PSIZE have no authority over the checksummed compressed stream.
            image.poison(ROOT, 1, 1024);
        }
        let reads = image.reads();
        let root = image.open(&faults, false).root(&cx, 0, 2, 123).unwrap();
        assert_eq!(root.data, expected);
        assert!(!root.raidz.unwrap().parity_read);
        assert_eq!(count(&reads, parity), 0);
    }
}

#[test]
fn two_failures_exceed_the_one_column_budget_and_cannot_return_unchecked_bytes() {
    let cx = Cx::for_testing();
    for case in 0..4 {
        let mut image = StripedImage::root(Endian::Big, 3, 9, false);
        let parity = image.column(ROOT, 0);
        let first = image.column(ROOT, 1);
        let second = image.column(ROOT, 2);
        let mut faults = vec![Fault::None; 3];
        match case {
            0 => {
                faults[first.0] = Fault::Io(first.1);
                faults[second.0] = Fault::Io(second.1);
            }
            1 => {
                faults[first.0] = Fault::Io(first.1);
                faults[parity.0] = Fault::Io(parity.1);
            }
            2 => {
                image.poison(ROOT, 1, 0);
                image.poison(ROOT, 2, 32);
            }
            _ => {
                image.poison(ROOT, 1, 0);
                image.poison(ROOT, 0, 32);
            }
        }
        let reads = image.reads();
        assert!(
            image.open(&faults, false).root(&cx, 0, 2, 123).is_err(),
            "case {case}"
        );
        assert_eq!(count(&reads, first), 1);
        assert_eq!(count(&reads, second), 1);
        assert_eq!(count(&reads, parity), usize::from(case != 0));
    }
}

#[test]
fn another_declared_dva_can_recover_an_unreadable_stripe_but_all_copy_failure_is_an_error() {
    let cx = Cx::for_testing();
    for all_bad in [false, true] {
        let mut image = StripedImage::root(Endian::Little, 3, 9, false);
        let second = image.add_root_copy(0x30_0000);
        let expected = image.root.clone();
        image.poison(ROOT, 1, 0);
        image.poison(ROOT, 2, 32);
        if all_bad {
            image.poison(second, 1, 0);
            image.poison(second, 2, 32);
        }
        let result = image.open(&[Fault::None; 3], true).root(&cx, 0, 2, 123);
        if all_bad {
            assert!(result.is_err());
        } else {
            let root = result.unwrap();
            assert_eq!(root.data, expected);
            assert_eq!(root.copy_index, 1);
            assert_eq!(root.raidz.unwrap().dva_offset, second - DATA_OFFSET);
        }
    }
}

#[test]
fn cancellation_stops_data_or_parity_reads_without_trying_another_dva() {
    let cx = Cx::for_testing();
    for ordinal in [1, 2, 0] {
        let mut image = StripedImage::root(Endian::Little, 3, 9, false);
        let copy = image.add_root_copy(0x30_0000);
        if ordinal == 0 {
            image.poison(ROOT, 1, 0);
        }
        let cancel = image.column(ROOT, ordinal);
        let parity = image.column(ROOT, 0);
        let second_data = image.column(ROOT, 2);
        let next: Vec<_> = image
            .map(copy)
            .columns()
            .iter()
            .enumerate()
            .map(|(index, _)| image.column(copy, index))
            .collect();
        let mut faults = vec![Fault::None; 3];
        faults[cancel.0] = Fault::Cancel(cancel.1);
        let reads = image.reads();
        assert!(matches!(
            image.open(&faults, true).root(&cx, 0, 2, 123),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(count(&reads, cancel), 1);
        assert_eq!(count(&reads, parity), usize::from(ordinal == 0));
        assert_eq!(count(&reads, second_data), usize::from(ordinal != 1));
        assert_no_payload(&reads, &next);
    }
}

fn tree(config: &mut NvList) -> &mut NvList {
    let Value::List(tree) = config.fields.get_mut("vdev_tree").unwrap() else {
        panic!("fixture tree");
    };
    tree
}

fn alter_topology(config: &mut NvList, case: u8) {
    let native = tree(config);
    match case {
        0..=2 => {
            native.fields.insert(
                "nparity".into(),
                Value::Unsigned([0, 4, 3][usize::from(case)]),
            );
        }
        3 => {
            native.fields.remove("nparity");
        }
        4 => {
            native
                .fields
                .insert("type".into(), Value::String("draid".into()));
        }
        5 => {
            native
                .fields
                .insert("raidz_expanding".into(), Value::Unsigned(0));
        }
        6 => {
            native
                .fields
                .insert("raidz_expand_txgs".into(), Value::Unsigned(0));
        }
        7 => {
            native
                .fields
                .insert("asize".into(), Value::Unsigned(3 * 512 + 1));
        }
        8 => {
            native
                .fields
                .insert("asize".into(), Value::Unsigned(3 * LENGTH as u64));
        }
        _ => {
            let Value::Lists(children) = native.fields.get_mut("children").unwrap() else {
                panic!("fixture children");
            };
            match case {
                9 => {
                    children[1].fields.insert("id".into(), Value::Unsigned(0));
                }
                10 => {
                    children[1]
                        .fields
                        .insert("guid".into(), Value::Unsigned(1001));
                }
                11 => {
                    children[1]
                        .fields
                        .insert("is_spare".into(), Value::Unsigned(1));
                }
                _ => {
                    children[1]
                        .fields
                        .insert("type".into(), Value::String("mirror".into()));
                }
            }
        }
    }
}

#[test]
fn unsupported_topology_expansion_and_invalid_capacity_fail_before_any_data_read() {
    let cx = Cx::for_testing();
    for case in 0..13 {
        let mut image = StripedImage::root(Endian::Little, 3, 9, false);
        let locations = root_locations(&image);
        for config in &mut image.configs {
            alter_topology(config, case);
        }
        image.refresh_labels();
        let reads = image.reads();
        assert!(
            image
                .open(&[Fault::None; 3], true)
                .root(&cx, 0, 2, 123)
                .is_err(),
            "case {case}"
        );
        assert_no_payload(&reads, &locations);
    }
}

#[test]
fn every_dva_and_every_label_must_agree_before_a_valid_first_stripe_is_read() {
    let cx = Cx::for_testing();
    for case in 0..6 {
        let mut image = StripedImage::root(Endian::Big, 3, 9, false);
        let locations = root_locations(&image);
        match case {
            0 => {
                let old = image.order.u64(&image.uberblock, 40).unwrap();
                image.uberblock[40..48].copy_from_slice(&image.order.encode(old + 1));
            }
            1 => {
                image.add_root_copy(0x30_0000);
                image.uberblock[56..64].copy_from_slice(&image.order.encode((1_u64 << 32) | 4));
            }
            2 => {
                image.add_root_copy(0x30_0000);
                image.uberblock[64..72]
                    .copy_from_slice(&image.order.encode(LENGTH as u64 * 10 / 512));
            }
            3 => {
                image.configs[1]
                    .fields
                    .insert("guid".into(), Value::Unsigned(1001));
            }
            4 => {
                let sum = image.order.u64(&image.uberblock, 24).unwrap();
                image.uberblock[24..32].copy_from_slice(&image.order.encode(sum + 1));
            }
            _ => {}
        }
        image.refresh_labels();
        if case == 5 {
            let mut config = image.configs[1].clone();
            config.fields.insert("txg".into(), Value::Unsigned(41));
            let packed = repack(&config);
            let offset = label_offsets(LENGTH as u64).unwrap()[3] + LABEL_CONFIG_OFFSET;
            let mut raw = vec![0; LABEL_CONFIG_BYTES];
            raw[..packed.len()].copy_from_slice(&packed);
            stamp(&mut raw, offset, image.order);
            let at = BASE + offset as usize;
            image.members[1][at..at + raw.len()].copy_from_slice(&raw);
        }
        let reads = image.reads();
        assert!(
            image
                .open(&[Fault::None; 3], false)
                .root(&cx, 0, 2, 123)
                .is_err(),
            "case {case}"
        );
        assert_no_payload(&reads, &locations);
    }
}
