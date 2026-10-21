//! Automatic selection through the existing native-label/DMU fixture.
//! These are constructed images, not a native OpenZFS interchange oracle.

use super::*;
use ffs_ondisk::zfs::{
    LABEL_CONFIG_BYTES, LABEL_CONFIG_OFFSET, UBERBLOCK_RING_BYTES, UBERBLOCK_RING_OFFSET,
    label_offsets,
};
use sha2::{Digest, Sha256};

fn stamp(raw: &mut [u8], offset: u64, order: Endian) {
    let trailer = raw.len() - 40;
    word(raw, trailer, 0x0210_da7a_b10c_7a11, order);
    raw[trailer + 8..].fill(0);
    word(raw, trailer + 8, offset, order);
    let digest = Sha256::digest(&*raw);
    for index in 0..4 {
        let value = u64::from_be_bytes(std::array::from_fn(|at| digest[index * 8 + at]));
        word(raw, trailer + 8 + index * 8, value, order);
    }
}

impl Fixture {
    fn clear_rings(&mut self) {
        for (member, image) in self.images.iter_mut().enumerate() {
            for label in label_offsets(self.lengths[member]).unwrap() {
                let start = BASE + (label + UBERBLOCK_RING_OFFSET) as usize;
                image[start..start + UBERBLOCK_RING_BYTES].fill(0);
            }
        }
    }

    fn candidate(&mut self, member: usize, label: usize, slot: usize, ub: &[u8]) {
        assert_eq!(ub.len(), self.ubs[member].len());
        assert!(slot < UBERBLOCK_RING_BYTES / ub.len());
        let offset = label_offsets(self.lengths[member]).unwrap()[label]
            + UBERBLOCK_RING_OFFSET
            + (slot * ub.len()) as u64;
        let mut raw = ub.to_vec();
        stamp(&mut raw, offset, self.order);
        let start = BASE + offset as usize;
        self.images[member][start..start + raw.len()].copy_from_slice(&raw);
    }

    fn damage_label(&mut self, member: usize, label: usize) {
        let offset = label_offsets(self.lengths[member]).unwrap()[label] + LABEL_CONFIG_OFFSET;
        self.images[member][BASE + offset as usize] ^= 1;
    }

    fn replace_label(&mut self, member: usize, label: usize, config: &NvList) {
        let offset = label_offsets(self.lengths[member]).unwrap()[label] + LABEL_CONFIG_OFFSET;
        let mut raw = vec![0; LABEL_CONFIG_BYTES];
        let packed = repack(config);
        raw[..packed.len()].copy_from_slice(&packed);
        stamp(&mut raw, offset, self.order);
        let start = BASE + offset as usize;
        self.images[member][start..start + raw.len()].copy_from_slice(&raw);
    }
}

#[test]
fn striped_mirror_auto_import_retains_mixed_geometry_and_independent_ring_locations() {
    let cx = Cx::for_testing();
    for widths in [[1, 1], [2, 2], [3, 2], [1, 2], [2, 1]] {
        for shifts in [[9, 9], [9, 12], [16, 12]] {
            for order in [Endian::Little, Endian::Big] {
                let mut fixture = Fixture::new(widths, shifts, order);
                let count = fixture.images.len();
                fixture.clear_rings();
                let candidate_member = fixture.groups[0][0];
                let ub = fixture.ubs[candidate_member].clone();
                fixture.candidate(candidate_member, 3, 1, &ub);
                fixture.damage_label(candidate_member, 3);
                fixture.damage_label(count - 1, 0);
                if widths[0] > 1 {
                    fixture.poison(fixture.groups[0][0], TABLE);
                }
                if widths[1] > 1 {
                    fixture.poison(fixture.groups[1][0], ROOT);
                    fixture.poison(fixture.groups[1][0], DATA);
                }
                let expected_guid = fixture.guids[*fixture.groups[1].last().unwrap()];
                let expected = fixture.root.clone();
                let supplied: Vec<_> = (0..count).rev().collect();
                let pool = fixture.pool(&supplied, &vec![Fault::None; count]);
                let (label, slot, root) = pool.import_active(&cx, Some(123)).unwrap();
                assert_eq!((label, slot), (3, 1));
                assert_eq!(root.uberblock.txg, 43);
                assert_eq!(root.member_guid, expected_guid);
                assert_eq!(root.data, expected);
                assert_eq!(root.config.total_data_bytes(), capacity(0) + capacity(1));
                assert_eq!(root.config.raidz_members.as_ref().unwrap().members.len(), 2);
                let mut objects = pool.import_objects(&cx, Some(123)).unwrap();
                drop(pool);
                assert_eq!(objects.read(&cx, 1, 7, 400).unwrap(), vec![0xA5; 400]);
                let mut cold = objects.clone_mos();
                drop(objects);
                assert_eq!(cold.read(&cx, 1, 0, 512).unwrap(), vec![0xA5; 512]);
            }
        }
    }
}

#[test]
fn striped_mirror_auto_import_keeps_explicit_selection_strict() {
    let cx = Cx::for_testing();
    let mut fixture = Fixture::new([2, 2], [9, 12], Endian::Little);
    fixture.damage_label(0, 0);
    fixture.damage_label(3, 1);
    let logs = fixture.logs.clone();
    let pool = fixture.pool(&[3, 0, 2, 1], &[Fault::None; 4]);
    assert!(pool.root(&cx, 2, 2, 123).is_err());
    Fixture::no_payload(&logs);
    assert_eq!(pool.import_active(&cx, None).unwrap().2.uberblock.txg, 43);
    assert_eq!(
        pool.import_objects(&cx, None).unwrap().read(&cx, 1, 0, 512).unwrap(),
        vec![0xA5; 512]
    );
}

#[test]
fn striped_mirror_auto_import_rejects_incomplete_and_conflicting_topology_before_payload() {
    let cx = Cx::for_testing();
    for case in 0..10 {
        let mut fixture = Fixture::new([2, 2], [9, 12], Endian::Little);
        let mut supplied = vec![3, 2, 1, 0];
        match case {
            0 => supplied = vec![0, 1, 2],
            1 => supplied = vec![0, 1, 2, 2],
            2 => supplied = vec![0, 1],
            3 => {
                tree(&mut fixture.configs[0])
                    .fields
                    .insert("asize".into(), Value::Unsigned(capacity(0) - 512));
            }
            4 => {
                for cfg in &mut fixture.configs[2..] {
                    cfg.fields.insert("top_guid".into(), Value::Unsigned(500));
                    tree(cfg).fields.insert("guid".into(), Value::Unsigned(500));
                }
            }
            5 => {
                for cfg in &mut fixture.configs {
                    cfg.fields.insert("vdev_children".into(), Value::Unsigned(3));
                }
            }
            6 => fixture.lengths[0] -= LABEL_BYTES,
            7 => {
                fixture.configs[3].fields.insert("state".into(), Value::Unsigned(0));
            }
            8 => {
                let Value::Lists(children) = tree(&mut fixture.configs[2])
                    .fields.get_mut("children").unwrap() else { panic!("children"); };
                children[0].fields.insert("id".into(), Value::Unsigned(7));
            }
            _ => {
                for cfg in &mut fixture.configs {
                    tree(cfg).fields.insert("type".into(), Value::String("replacing".into()));
                }
            }
        }
        fixture.labels();
        let logs = fixture.logs.clone();
        let pool = fixture.pool(&supplied, &[Fault::None; 4]);
        assert!(pool.import_active(&cx, Some(123)).is_err(), "case {case}");
        Fixture::no_payload(&logs);
    }
}

#[test]
fn striped_mirror_auto_import_requires_every_valid_label_to_agree() {
    let cx = Cx::for_testing();
    for case in 0..4 {
        let mut fixture = Fixture::new([2, 2], [9, 12], Endian::Big);
        if case == 3 {
            for label in 0..4 { fixture.damage_label(1, label); }
        } else {
            let mut cfg = fixture.configs[1].clone();
            match case {
                0 => { cfg.fields.insert("guid".into(), Value::Unsigned(1000)); }
                1 => { cfg.fields.insert("txg".into(), Value::Unsigned(44)); }
                _ => { cfg.fields.insert("pool_guid".into(), Value::Unsigned(456)); }
            }
            fixture.replace_label(1, 3, &cfg);
        }
        let logs = fixture.logs.clone();
        let pool = fixture.pool(&[3, 2, 1, 0], &[Fault::None; 4]);
        assert!(pool.import_active(&cx, Some(123)).is_err(), "case {case}");
        Fixture::no_payload(&logs);
    }
}

#[test]
fn striped_mirror_auto_import_filters_guid_sum_and_config_age_and_rejects_txg_forks() {
    let cx = Cx::for_testing();
    for case in 0..3 {
        let mut fixture = Fixture::new([2, 2], [9, 12], Endian::Little);
        let mut ub = fixture.ubs[0].clone();
        match case {
            0 => {
                word(&mut ub, 24, 123 + 500 + 501, fixture.order);
                fixture.clear_rings();
            }
            1 => {
                word(&mut ub, 16, 40, fixture.order);
                fixture.clear_rings();
            }
            _ => {
                word(&mut ub, 48, OTHER / 512, fixture.order);
            }
        }
        fixture.candidate(0, 3, 1, &ub);
        let logs = fixture.logs.clone();
        let pool = fixture.pool(&[0, 1, 2, 3], &[Fault::None; 4]);
        assert!(pool.import_active(&cx, Some(123)).is_err(), "case {case}");
        Fixture::no_payload(&logs);
    }
}

#[test]
fn striped_mirror_auto_import_distinguishes_label_io_failure_from_cancellation() {
    let cx = Cx::for_testing();
    for offset in [LABEL_CONFIG_OFFSET, UBERBLOCK_RING_OFFSET, DATA_OFFSET + ROOT] {
        for cancel in [false, true] {
            let fixture = Fixture::new([2, 2], [9, 12], Endian::Little);
            let logs = fixture.logs.clone();
            let member = if offset == DATA_OFFSET + ROOT { 2 } else { 3 };
            let mut faults = [Fault::None; 4];
            faults[member] = if cancel {
                Fault::Cancel(BASE as u64 + offset)
            } else {
                Fault::Io(BASE as u64 + offset)
            };
            let pool = fixture.pool(&[0, 1, 2, 3], &faults);
            let result = pool.import_active(&cx, Some(123));
            if cancel {
                assert!(matches!(result, Err(FfsError::Cancelled)));
                if offset == DATA_OFFSET + ROOT {
                    assert!(!logs[3].lock().unwrap().iter()
                        .any(|(position, _)| *position == at(ROOT) as u64));
                } else {
                    Fixture::no_payload(&logs);
                }
            } else {
                assert_eq!(result.unwrap().2.uberblock.txg, 43);
            }
        }
    }
}

#[test]
fn striped_mirror_auto_import_retains_all_replicas_for_redundancy_scrub() {
    let cx = Cx::for_testing();
    let mut fixture = Fixture::new([3, 2], [9, 12], Endian::Big);
    fixture.poison(1, TABLE);
    fixture.poison(4, DATA);
    fixture.damage_label(4, 0);
    let logs = fixture.logs.clone();
    let mut objects = fixture.pool(&[4, 2, 0, 3, 1], &[Fault::None; 5])
        .import_objects(&cx, Some(123)).unwrap();
    assert_eq!(objects.read(&cx, 1, 0, 512).unwrap(), vec![0xA5; 512]);
    assert!(objects.scrub(&cx, ScrubLimits::default()).unwrap().is_clean());
    let report = objects.scrub(&cx, ScrubLimits {
        copy_bytes: Some(1 << 30),
        ..ScrubLimits::default()
    }).unwrap();
    assert!(!report.is_clean());
    assert_eq!(report.errors, 2);
    assert_eq!(report.verified_blocks, 2);
    assert_eq!(report.copies_examined, 5);
    for (index, log) in logs.iter().enumerate() {
        let expected = if index < 3 { TABLE } else { DATA };
        assert!(log.lock().unwrap().iter()
            .any(|(offset, _)| *offset == at(expected) as u64));
    }
}

#[test]
fn striped_mirror_auto_import_never_uses_bytes_from_an_unrelated_top_level() {
    let cx = Cx::for_testing();
    let mut fixture = Fixture::new([2, 2], [9, 12], Endian::Little);
    fixture.poison(2, ROOT);
    fixture.poison(3, ROOT);
    let root = fixture.root.clone();
    fixture.store(0, ROOT, &root);
    let logs = fixture.logs.clone();
    let pool = fixture.pool(&[3, 1, 0, 2], &[Fault::None; 4]);
    assert!(pool.import_active(&cx, Some(123)).is_err());
    for log in &logs[..2] {
        assert!(!log.lock().unwrap().iter()
            .any(|(position, _)| *position == at(ROOT) as u64));
    }
    for log in &logs[2..] {
        assert_eq!(log.lock().unwrap().iter()
            .filter(|(position, _)| *position == at(ROOT) as u64).count(), 1);
    }
}
