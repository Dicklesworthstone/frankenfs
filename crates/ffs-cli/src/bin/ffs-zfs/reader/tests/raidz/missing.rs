//! Real absent handles, not I/O-error stand-ins for configured disks.
//! These use the existing independent fixture encoder and verified native reader.

use super::*;
use crate::reader::{Leaf, Pool};
use std::collections::BTreeSet;

fn survivors(pool: &Pool, absent: &[usize], reverse: bool) -> Vec<Leaf> {
    let mut result: Vec<_> = pool.leaves().iter().enumerate()
        .filter(|(index, _)| !absent.contains(index))
        .map(|(_, leaf)| leaf.clone()).collect();
    if reverse { result.reverse(); }
    result
}

fn missing_pool(cx: &Cx, pool: &Pool, absent: &[usize], reverse: bool) -> Result<Pool> {
    Pool::from_raidz_survivors(
        cx,
        survivors(pool, absent, reverse),
        absent.iter().map(|index| 1001 + *index as u64).collect(),
    )
}

fn clear_reads(reads: &[Reads]) {
    for log in reads { log.lock().unwrap().clear(); }
}

#[test]
fn missing_raidz_all_admitted_erasure_sets_keep_native_width_and_verified_contents() {
    let cx = Cx::for_testing();
    for parity in 1..=3 {
        for width in [parity + 1, 8] {
            for order in [Endian::Little, Endian::Big] {
                let image = StripedImage::root_with_parity(order, width, 9, false, parity);
                let expected = image.root.clone();
                let map = image.map(ROOT).clone();
                let first_data_guid = 1001 + map.columns()[parity].child_id as u64;
                let logs = image.reads();
                let complete = image.open(&vec![Fault::None; width], false);
                for mask in 1_u16..1_u16 << width {
                    if mask.count_ones() as usize > parity { continue; }
                    let absent: Vec<_> = (0..width).filter(|&index| mask & (1 << index) != 0).collect();
                    clear_reads(&logs);
                    let pool = missing_pool(&cx, &complete, &absent, !mask.is_multiple_of(2)).unwrap();
                    let root = pool.root(&cx, 0, 2, 123).unwrap();
                    assert_eq!(root.data, expected, "RAIDZ{parity}/{width} missing {absent:?}");
                    assert_eq!(root.member_guid, first_data_guid);
                    assert_eq!(root.uberblock.txg, 43);
                    let group = root.config.raidz_members.as_ref().unwrap();
                    assert_eq!(group.members.len(), width);
                    assert_eq!(group.parity, parity);
                    assert_eq!(group.members.iter().filter(|member| member.supplied_index == usize::MAX).count(), absent.len());
                    let wanted: BTreeSet<_> = map.columns().iter()
                        .filter(|column| column.data_offset.is_some() && absent.contains(&column.child_id))
                        .map(|column| column.child_id).collect();
                    let stripe = root.raidz.unwrap();
                    assert_eq!(stripe.parity_read, !wanted.is_empty());
                    assert_eq!(stripe.reconstructed_children.iter().copied().collect::<BTreeSet<_>>(), wanted);
                    assert_eq!(stripe.allocated_bytes, map.allocated_bytes());
                    for (actual, native) in stripe.columns.iter().zip(map.columns()) {
                        assert_eq!((actual.child_id, actual.member_guid, actual.bytes),
                            (native.child_id, 1001 + native.child_id as u64, native.bytes));
                    }
                    for (index, log) in logs.iter().enumerate() {
                        let reads = log.lock().unwrap();
                        if absent.contains(&index) { assert!(reads.is_empty()); }
                        assert!(reads.iter().all(|(at, bytes)| *at >= BASE as u64 && *at + *bytes as u64 <= (BASE + LENGTH) as u64));
                    }
                }
            }
        }
    }
}

#[test]
fn missing_raidz_large_sectors_compression_and_one_survivor_are_not_standalone_leaves() {
    let cx = Cx::for_testing();
    for parity in 1..=3 {
        for ashift in [12, 16] {
            for compressed in [false, true] {
                for order in [Endian::Little, Endian::Big] {
                    let width = parity + 1;
                    let image = StripedImage::root_with_parity(order, width, ashift, compressed, parity);
                    let expected = image.root.clone();
                    let first_data = image.map(ROOT).columns()[parity].child_id;
                    let surviving = image.map(ROOT).columns()[0].child_id;
                    let absent: Vec<_> = (0..width).filter(|id| *id != surviving).collect();
                    assert!(absent.contains(&first_data));
                    let complete = image.open(&vec![Fault::None; width], false);
                    let pool = missing_pool(&cx, &complete, &absent, true).unwrap();
                    drop(complete);
                    assert!(pool.standalone_leaf().is_none());
                    let root = pool.root(&cx, 3, 2, 123).unwrap();
                    assert_eq!(root.data, expected);
                    assert_eq!(root.member_guid, 1001 + first_data as u64);
                    assert!(root.raidz.unwrap().reconstructed_children.contains(&first_data));
                }
            }
        }
    }
}

#[test]
fn missing_raidz_membership_is_exact_and_default_import_does_not_infer_absence() {
    let cx = Cx::for_testing();
    let image = StripedImage::root_with_parity(Endian::Little, 4, 9, false, 2);
    let locations = root_locations(&image);
    let logs = image.reads();
    let complete = image.open(&[Fault::None; 4], false);
    for missing in [vec![], vec![0], vec![1004, 1004], vec![9999], vec![1001], vec![1003, 1004]] {
        assert!(Pool::from_raidz_survivors(&cx, survivors(&complete, &[3], false), missing).is_err());
        assert_no_payload(&logs, &locations);
    }
    let mut duplicate = survivors(&complete, &[2, 3], false);
    duplicate[1] = duplicate[0].clone();
    assert!(Pool::from_raidz_survivors(&cx, duplicate, vec![1003, 1004]).is_err());
    let strict = Pool::from_leaves(survivors(&complete, &[3], false)).unwrap();
    assert!(strict.root(&cx, 0, 2, 123).is_err());
    assert!(strict.import_active(&cx, Some(123)).is_err());
    let explicit = missing_pool(&cx, &complete, &[2, 3], true).unwrap();
    assert!(explicit.import_active(&cx, Some(123)).is_err());
    assert!(explicit.root(&cx, 0, 2, 124).is_err());
    assert_no_payload(&logs, &locations);
    assert!(explicit.root(&cx, 0, 2, 123).is_ok());
}

#[test]
fn missing_raidz_refuses_active_expanded_nonraidz_and_excess_erasure_profiles() {
    let cx = Cx::for_testing();
    for case in 0..6 {
        let mut image = StripedImage::root_with_parity(Endian::Little, 4, 9, false, 2);
        let locations = root_locations(&image);
        for config in &mut image.configs {
            match case {
                0 => { config.fields.insert("state".into(), Value::Unsigned(0)); }
                1 => { tree(config).fields.insert("raidz_expanding".into(), Value::Unsigned(0)); }
                2 => { tree(config).fields.insert("type".into(), Value::String("mirror".into())); }
                3 => { tree(config).fields.insert("nparity".into(), Value::Unsigned(1)); }
                4 => { config.fields.insert("vdev_children".into(), Value::Unsigned(2)); }
                _ => { tree(config).fields.insert("allocation_bias".into(), Value::String("special".into())); }
            }
        }
        image.refresh_labels();
        let logs = image.reads();
        let complete = image.open(&[Fault::None; 4], false);
        assert!(missing_pool(&cx, &complete, &[2, 3], false).is_err(), "case {case}");
        assert_no_payload(&logs, &locations);
    }
    for (supplied, missing) in [(0, vec![1]), (1, vec![]), (7, vec![1, 2]), (1, vec![1, 2, 3, 4])] {
        assert!(Pool::check_raidz_survivors(supplied, &missing).is_err());
    }
}

#[test]
fn missing_raidz_checks_every_dva_full_guid_sum_and_survivor_label_before_payload() {
    let cx = Cx::for_testing();
    for case in 0..5 {
        let mut image = StripedImage::root_with_parity(Endian::Big, 4, 9, false, 2);
        let locations = root_locations(&image);
        match case {
            0 => {
                let sum = image.order.u64(&image.uberblock, 24).unwrap();
                image.uberblock[24..32].copy_from_slice(&image.order.encode(sum - 1004));
            }
            1 => {
                image.add_root_copy(0x30_0000);
                image.uberblock[64..72].copy_from_slice(&image.order.encode(LENGTH as u64 * 10 / 512));
            }
            2 => {
                image.add_root_copy(0x30_0000);
                let asize = image.order.u64(&image.uberblock, 56).unwrap();
                image.uberblock[56..64].copy_from_slice(&image.order.encode(asize | (1_u64 << 32)));
            }
            3 => {
                for config in &mut image.configs {
                    tree(config).fields.insert("asize".into(), Value::Unsigned(4 * LENGTH as u64));
                }
            }
            _ => {}
        }
        image.refresh_labels();
        if case == 4 {
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
        let logs = image.reads();
        let complete = image.open(&[Fault::None; 4], false);
        let result = missing_pool(&cx, &complete, &[3], true)
            .and_then(|pool| pool.root(&cx, 0, 2, 123));
        assert!(result.is_err(), "case {case}");
        assert_no_payload(&logs, &locations);
    }
}

#[test]
fn missing_raidz_declared_erasures_and_bad_readable_parity_share_the_native_budget() {
    let cx = Cx::for_testing();
    for parity in 1..=3 {
        let width = parity + 2;
        for too_many in [false, true] {
            let mut image = StripedImage::root_with_parity(Endian::Little, width, 9, false, parity);
            let expected = image.root.clone();
            let lost = image.column(ROOT, parity).0;
            // A single absent data column. Corrupt P; Q/R must recover where
            // available. With every parity corrupt no candidate may verify.
            for ordinal in 0..if too_many { parity } else { 1 } {
                image.poison(ROOT, ordinal, 0);
            }
            let complete = image.open(&vec![Fault::None; width], false);
            let result = missing_pool(&cx, &complete, &[lost], true).unwrap().root(&cx, 0, 2, 123);
            if too_many || parity == 1 {
                assert!(result.is_err());
            } else {
                let root = result.unwrap();
                assert_eq!(root.data, expected);
                assert!(root.raidz.unwrap().reconstructed_children.contains(&lost));
            }
        }
    }
}

#[test]
fn missing_raidz_retries_declared_copies_but_cancellation_is_terminal() {
    let cx = Cx::for_testing();
    for cancel in [false, true] {
        let mut image = StripedImage::root_with_parity(Endian::Little, 3, 9, false, 1);
        let expected = image.root.clone();
        let copy = image.add_root_copy(0x30_0000);
        let absent = image.column(ROOT, 1).0;
        let parity = image.column(ROOT, 0);
        let next: Vec<_> = image.map(copy).columns().iter().enumerate()
            .filter(|(_, column)| column.bytes != 0)
            .map(|(index, _)| image.column(copy, index)).collect();
        let mut faults = vec![Fault::None; 3];
        faults[parity.0] = if cancel { Fault::Cancel(parity.1) } else { Fault::Io(parity.1) };
        let logs = image.reads();
        let complete = image.open(&faults, false);
        let result = missing_pool(&cx, &complete, &[absent], true).unwrap().root(&cx, 0, 2, 123);
        if cancel {
            assert!(matches!(result, Err(FfsError::Cancelled)));
            assert_no_payload(&logs, &next);
        } else {
            let root = result.unwrap();
            assert_eq!(root.copy_index, 1);
            assert_eq!(root.data, expected);
        }
        assert_eq!(count(&logs, parity), 1);
        assert!(logs[absent].lock().unwrap().is_empty());
    }
}

#[test]
fn missing_raidz_routes_cannot_alias_present_handles_or_invent_undeclared_absences() {
    let cx = Cx::for_testing();
    let image = StripedImage::root_with_parity(Endian::Little, 3, 9, false, 1);
    let logs = image.reads();
    let complete = image.open(&[Fault::None; 3], false);
    let pool = missing_pool(&cx, &complete, &[2], false).unwrap();
    let root = pool.root(&cx, 0, 2, 123).unwrap();
    for case in 0..3 {
        let mut config = root.config.clone();
        let group = config.raidz_members.as_mut().unwrap();
        match case {
            0 => group.members[2].supplied_index = 0,
            1 => group.members[0].supplied_index = usize::MAX,
            _ => group.members[1].supplied_index = 0,
        }
        clear_reads(&logs);
        assert!(pool.read_block(&cx, &config, &root.uberblock.root).is_err());
        assert!(logs.iter().all(|log| log.lock().unwrap().is_empty()));
    }
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(asupersync::types::CancelKind::User, Some("absent RAIDZ control"));
    clear_reads(&logs);
    assert!(matches!(missing_pool(&cancelled, &complete, &[2], false), Err(FfsError::Cancelled)));
    assert!(logs.iter().all(|log| log.lock().unwrap().is_empty()));
}
