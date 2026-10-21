//! Constructed native labels/DMU graphs, not OpenZFS interchange qualification.

use super::*;
use crate::reader::dmu::scrub::ScrubLimits;
use crate::reader::tests::mirror::{Fault, install_labels, native_config, open_bytes, repack};
use crate::reader::{BlockPointer, Endian, FfsError};
use ffs_ondisk::zfs::{checksum, uberblock_bytes};
use std::sync::Mutex;

mod auto_import;

type Reads = Arc<Mutex<Vec<(u64, usize)>>>;
const BASE: usize = 1024;
const LENGTH: usize = 8 * 1024 * 1024;
const ROOT: u64 = 0x1_0000;
const TABLE: u64 = 0x2_0000;
const DATA: u64 = 0x4_0000;
const OTHER: u64 = 0x6_0000;
const FIRST: u64 = 0x8_0000;
const SECOND: u64 = 0xA_0000;

fn at(offset: u64) -> usize {
    BASE + (DATA_OFFSET + offset) as usize
}
fn capacity(id: usize) -> u64 {
    LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES - id as u64 * 65536
}
fn word(bytes: &mut [u8], at: usize, value: u64, order: Endian) {
    bytes[at..at + 8].copy_from_slice(&order.encode(value));
}
fn bp(
    bytes: &[u8],
    vdev: u32,
    offset: u64,
    ashift: u8,
    kind: u8,
    birth: u64,
    order: Endian,
) -> [u8; 128] {
    let mut words = [0_u64; 16];
    let sector = 1_u64 << ashift;
    words[0] = (u64::from(vdev) << 32) | ((bytes.len() as u64).div_ceil(sector) * sector / 512);
    words[1] = offset / 512;
    let size = bytes.len() as u64 / 512 - 1;
    words[6] = size
        | (size << 16)
        | (2 << 32)
        | (7 << 40)
        | (u64::from(kind) << 48)
        | (u64::from(order == Endian::Little) << 63);
    words[10] = birth;
    words[12..].copy_from_slice(&checksum(bytes, 7, order).unwrap());
    let mut raw = [0; 128];
    for (index, value) in words.into_iter().enumerate() {
        word(&mut raw, index * 8, value, order);
    }
    raw
}
fn dnode(kind: u8, size: u16, pointer: &[u8; 128], order: Endian) -> [u8; 512] {
    let mut raw = [0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = 1;
    raw[3] = 1;
    raw[7] = 1;
    raw[8..10].copy_from_slice(&match order {
        Endian::Little => size.to_le_bytes(),
        Endian::Big => size.to_be_bytes(),
    });
    raw[64..192].copy_from_slice(pointer);
    raw
}
fn tree(config: &mut NvList) -> &mut NvList {
    let Value::List(tree) = config.fields.get_mut("vdev_tree").unwrap() else {
        panic!("tree");
    };
    tree
}

struct Fixture {
    images: Vec<Vec<u8>>,
    configs: Vec<NvList>,
    ubs: Vec<Vec<u8>>,
    logs: Vec<Reads>,
    lengths: Vec<u64>,
    groups: [Vec<usize>; 2],
    guids: Vec<u64>,
    shifts: [u8; 2],
    order: Endian,
    root: Vec<u8>,
    table: Vec<u8>,
}

impl Fixture {
    fn new(widths: [usize; 2], shifts: [u8; 2], order: Endian) -> Self {
        let width = widths.iter().sum();
        let mut result = Self {
            images: vec![vec![0; BASE + LENGTH + 512]; width],
            configs: Vec::new(),
            ubs: Vec::new(),
            logs: (0..width).map(|_| Arc::default()).collect(),
            lengths: vec![LENGTH as u64; width],
            groups: [Vec::new(), Vec::new()],
            guids: Vec::new(),
            shifts,
            order,
            root: vec![0; 1024],
            table: vec![0; 16384],
        };
        let mut sum = 123_u64;
        for (id, &count) in widths.iter().enumerate() {
            let top_guid = 500 + id as u64;
            sum += top_guid;
            let guids: Vec<_> = (0..count)
                .map(|child| {
                    if count == 1 {
                        top_guid
                    } else {
                        1000 + 16 * id as u64 + child as u64
                    }
                })
                .collect();
            if count != 1 {
                sum += guids.iter().sum::<u64>();
            }
            for &guid in &guids {
                result.groups[id].push(result.configs.len());
                result.guids.push(guid);
                let raw = native_config(
                    guid,
                    &guids,
                    u64::from(shifts[id]),
                    capacity(id),
                    40 + id as u64,
                );
                let mut cfg = NvList::parse(&raw).unwrap();
                cfg.fields.insert("version".into(), Value::Unsigned(28));
                cfg.fields.remove("features_for_read");
                cfg.fields
                    .insert("top_guid".into(), Value::Unsigned(top_guid));
                cfg.fields
                    .insert("vdev_children".into(), Value::Unsigned(2));
                let native = tree(&mut cfg);
                native
                    .fields
                    .insert("id".into(), Value::Unsigned(id as u64));
                native
                    .fields
                    .insert("guid".into(), Value::Unsigned(top_guid));
                if count == 1 {
                    native
                        .fields
                        .insert("type".into(), Value::String("file".into()));
                    native.fields.remove("children");
                }
                result.configs.push(cfg);
                let mut ub = vec![0; uberblock_bytes(shifts[id]).unwrap()];
                for (at, value) in [(0, 0x00BA_B10C), (8, 28), (16, 43), (32, 100)] {
                    word(&mut ub, at, value, order);
                }
                result.ubs.push(ub);
            }
        }
        for image in &mut result.images {
            image[..BASE].fill(0xD1);
            image[BASE + LENGTH..].fill(0xD2);
        }
        for ub in &mut result.ubs {
            word(ub, 24, sum, order);
        }
        let data = vec![0xA5; 512];
        let pointer = bp(&data, 1, DATA, shifts[1], 19, 20, order);
        result.table[512..1024].copy_from_slice(&dnode(19, 1, &pointer, order));
        result.store(1, DATA, &data);
        result.publish_graph();
        result
    }
    fn store(&mut self, id: usize, offset: u64, bytes: &[u8]) {
        for &member in &self.groups[id] {
            self.images[member][at(offset)..at(offset) + bytes.len()].copy_from_slice(bytes);
        }
    }
    fn labels(&mut self) {
        for member in 0..self.images.len() {
            install_labels(
                &mut self.images[member],
                BASE,
                self.lengths[member],
                self.order,
                &repack(&self.configs[member]),
                &self.ubs[member],
            );
        }
    }
    fn publish_graph(&mut self) {
        let table = self.table.clone();
        self.store(0, TABLE, &table);
        let pointer = bp(&table, 0, TABLE, self.shifts[0], 10, 30, self.order);
        self.root[..512].copy_from_slice(&dnode(10, 32, &pointer, self.order));
        word(&mut self.root, 704, 1, self.order);
        let root = self.root.clone();
        self.store(1, ROOT, &root);
        let pointer = bp(&root, 1, ROOT, self.shifts[1], 11, 40, self.order);
        for ub in &mut self.ubs {
            ub[40..168].copy_from_slice(&pointer);
        }
        self.labels();
    }
    fn poison(&mut self, member: usize, offset: u64) {
        self.images[member][at(offset)] ^= 0x5B;
    }
    fn pool(self, order: &[usize], faults: &[Fault]) -> Pool {
        let leaves = order
            .iter()
            .map(|&index| {
                open_bytes(
                    self.images[index].clone(),
                    BASE,
                    self.lengths[index],
                    Arc::clone(&self.logs[index]),
                    faults[index],
                )
            })
            .collect();
        Pool::from_leaves(leaves).unwrap()
    }
    fn no_payload(logs: &[Reads]) {
        for log in logs {
            assert!(log.lock().unwrap().iter().all(|(offset, _)| {
                ![ROOT, TABLE, DATA, OTHER, FIRST, SECOND]
                    .iter()
                    .any(|raw| *offset == at(*raw) as u64)
            }));
        }
    }
}

#[test]
fn striped_mirrors_route_native_ids_and_count_top_level_capacity_once() {
    let cx = Cx::for_testing();
    for widths in [[2, 2], [3, 2], [1, 2], [2, 1]] {
        for shifts in [[9, 9], [9, 12], [16, 12]] {
            for order in [Endian::Little, Endian::Big] {
                let fixture = Fixture::new(widths, shifts, order);
                let n = fixture.images.len();
                let expected_guid = fixture.guids[fixture.groups[1][0]];
                let expected = fixture.root.clone();
                let supplied: Vec<_> = (0..n).rev().collect();
                let pool = fixture.pool(&supplied, &vec![Fault::None; n]);
                let root = pool.root(&cx, 0, 2, 123).unwrap();
                assert_eq!(root.data, expected);
                assert_eq!(root.member_guid, expected_guid);
                assert_eq!(root.config.total_data_bytes(), capacity(0) + capacity(1));
                assert_eq!(root.config.raidz_members.as_ref().unwrap().members.len(), 2);
                assert!(root.raidz.is_none());
                let mut objects = pool.objects(&cx, 0, 2, 123).unwrap();
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
fn striped_mirror_fallback_never_uses_an_unrelated_vdev_without_a_declared_dva() {
    let cx = Cx::for_testing();
    for all_bad in [false, true] {
        let mut fixture = Fixture::new([2, 2], [9, 12], Endian::Little);
        fixture.poison(2, DATA);
        if all_bad {
            fixture.poison(3, DATA);
        }
        // Equal, correctly checksummed bytes on an unrelated vdev are NOT a replica.
        fixture.store(0, DATA, &[0xA5; 512]);
        let logs = fixture.logs.clone();
        let pool = fixture.pool(&[3, 1, 2, 0], &[Fault::None; 4]);
        let result = pool.objects(&cx, 0, 2, 123).unwrap().read(&cx, 1, 0, 512);
        if all_bad {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), vec![0xA5; 512]);
        }
        for log in &logs[..2] {
            assert!(
                !log.lock()
                    .unwrap()
                    .iter()
                    .any(|(offset, _)| *offset == at(DATA) as u64)
            );
        }
        for log in &logs[2..] {
            assert_eq!(
                log.lock()
                    .unwrap()
                    .iter()
                    .filter(|(offset, _)| *offset == at(DATA) as u64)
                    .count(),
                1
            );
        }
    }
}

#[test]
fn striped_mirror_declared_dva_fallback_and_cancellation_keep_physical_identity() {
    let cx = Cx::for_testing();
    for cancel in [false, true] {
        let mut fixture = Fixture::new([2, 2], [9, 12], Endian::Big);
        let root = fixture.root.clone();
        fixture.store(0, OTHER, &root);
        let second = bp(&root, 0, OTHER, 9, 11, 40, fixture.order);
        for ub in &mut fixture.ubs {
            ub[56..72].copy_from_slice(&second[..16]);
        }
        fixture.labels();
        fixture.poison(2, ROOT);
        fixture.poison(3, ROOT);
        let logs = fixture.logs.clone();
        let mut faults = [Fault::None; 4];
        if cancel {
            faults[3] = Fault::Cancel(at(ROOT) as u64);
        }
        let pool = fixture.pool(&[3, 2, 1, 0], &faults);
        let result = pool.root(&cx, 0, 2, 123);
        if cancel {
            assert!(matches!(result, Err(FfsError::Cancelled)));
            assert!(
                !logs[0]
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(offset, _)| *offset == at(OTHER) as u64)
            );
        } else {
            let root = result.unwrap();
            assert_eq!(root.copy_index, 1);
            assert_eq!(root.member_guid, 1000);
            assert_eq!(root.physical_offset, DATA_OFFSET + OTHER);
        }
    }
}

#[test]
fn striped_mirror_admission_refuses_incomplete_conflicting_and_foreign_topologies_before_payload() {
    let cx = Cx::for_testing();
    for case in 0..10 {
        let mut fixture = Fixture::new([2, 2], [9, 12], Endian::Little);
        let mut supplied = vec![3, 2, 1, 0];
        match case {
            0 => supplied = vec![0, 1, 2],
            1 => supplied = vec![0, 1, 2, 2],
            2 => {
                for cfg in &mut fixture.configs[2..] {
                    let Value::Lists(children) = tree(cfg).fields.get_mut("children").unwrap()
                    else {
                        panic!("children");
                    };
                    children[0].fields.insert("id".into(), Value::Unsigned(7));
                }
            }
            3 => {
                tree(&mut fixture.configs[0])
                    .fields
                    .insert("asize".into(), Value::Unsigned(capacity(0) - 512));
            }
            4 => {
                for ub in &mut fixture.ubs {
                    let sum = fixture.order.u64(ub, 24).unwrap();
                    word(ub, 24, sum + 1, fixture.order);
                }
            }
            5 => {
                for cfg in &mut fixture.configs {
                    cfg.fields.insert("state".into(), Value::Unsigned(0));
                }
            }
            6 => {
                for cfg in &mut fixture.configs[2..] {
                    cfg.fields.insert("top_guid".into(), Value::Unsigned(500));
                    tree(cfg).fields.insert("guid".into(), Value::Unsigned(500));
                }
            }
            7 => {
                for cfg in &mut fixture.configs {
                    cfg.fields
                        .insert("vdev_children".into(), Value::Unsigned(3));
                }
            }
            8 => {
                fixture.lengths[0] -= LABEL_BYTES;
            }
            _ => {
                // A valid first DVA cannot conceal a later foreign mapping.
                for ub in &mut fixture.ubs {
                    word(ub, 56, (7_u64 << 32) | 2, fixture.order);
                    word(ub, 64, OTHER / 512, fixture.order);
                }
            }
        }
        fixture.labels();
        let logs = fixture.logs.clone();
        assert!(
            fixture
                .pool(&supplied, &[Fault::None; 4])
                .root(&cx, 0, 2, 123)
                .is_err(),
            "case {case}"
        );
        Fixture::no_payload(&logs);
    }
}

#[test]
fn striped_mirror_scrub_visits_all_replicas_without_certifying_recovered_damage() {
    let cx = Cx::for_testing();
    let mut fixture = Fixture::new([3, 2], [9, 12], Endian::Little);
    fixture.poison(1, TABLE);
    fixture.poison(4, DATA);
    let logs = fixture.logs.clone();
    let mut objects = fixture
        .pool(&[4, 2, 0, 3, 1], &[Fault::None; 5])
        .objects(&cx, 0, 2, 123)
        .unwrap();
    assert_eq!(objects.read(&cx, 1, 0, 512).unwrap(), vec![0xA5; 512]);
    assert!(
        objects
            .scrub(&cx, ScrubLimits::default())
            .unwrap()
            .is_clean()
    );
    let report = objects
        .scrub(
            &cx,
            ScrubLimits {
                copy_bytes: Some(1 << 30),
                ..ScrubLimits::default()
            },
        )
        .unwrap();
    assert!(!report.is_clean());
    assert_eq!(report.errors, 2);
    assert_eq!(report.verified_blocks, 2);
    assert_eq!(report.copies_examined, 5);
    for (index, log) in logs.iter().enumerate() {
        let expected = if index < 3 { TABLE } else { DATA };
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .any(|(offset, _)| *offset == at(expected) as u64)
        );
    }
}

#[test]
fn striped_mirror_cancellation_in_unused_replica_and_copy_budget_stop_the_audit() {
    let cx = Cx::for_testing();
    let fixture = Fixture::new([2, 2], [9, 12], Endian::Little);
    let logs = fixture.logs.clone();
    let faults = [
        Fault::None,
        Fault::Cancel(at(TABLE) as u64),
        Fault::None,
        Fault::None,
    ];
    let objects = fixture
        .pool(&[2, 1, 0, 3], &faults)
        .objects(&cx, 0, 2, 123)
        .unwrap();
    assert!(
        objects
            .scrub(&cx, ScrubLimits::default())
            .unwrap()
            .is_clean()
    );
    for log in &logs {
        log.lock().unwrap().clear();
    }
    let report = objects
        .scrub(
            &cx,
            ScrubLimits {
                copy_bytes: Some(65535),
                ..ScrubLimits::default()
            },
        )
        .unwrap();
    assert_eq!(report.limit_reached, Some("physical-copy work budget"));
    assert_eq!(report.copy_work_bytes, 0);
    assert!(logs[1].lock().unwrap().is_empty());
    assert!(matches!(
        objects.scrub(
            &cx,
            ScrubLimits {
                copy_bytes: Some(1 << 30),
                ..ScrubLimits::default()
            }
        ),
        Err(FfsError::Cancelled)
    ));
}

#[test]
fn striped_mirror_gang_headers_and_cross_vdev_fragments_keep_every_replica() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let mut fixture = Fixture::new([2, 2], [12, 12], order);
        let first = vec![0x33; 512];
        let second = vec![0x77; 512];
        let payload = [first.clone(), second.clone()].concat();
        let a = bp(&first, 0, FIRST, 12, 0, 20, order);
        let b = bp(&second, 1, SECOND, 12, 0, 20, order);
        let mut leader = bp(&payload, 1, OTHER, 12, 19, 20, order);
        word(&mut leader, 0, (1_u64 << 32) | ((3 * 4096) / 512), order);
        word(&mut leader, 8, (1_u64 << 63) | (OTHER / 512), order);
        let mut header = [0; 512];
        header[..128].copy_from_slice(&a);
        header[128..256].copy_from_slice(&b);
        word(&mut header, 472, 0x0210_DA7A_B10C_7A11, order);
        for (index, value) in [1, OTHER, 20, 0].into_iter().enumerate() {
            word(&mut header, 480 + index * 8, value, order);
        }
        let digest = checksum(&header, 8, Endian::Big).unwrap();
        for (index, value) in digest.into_iter().enumerate() {
            word(&mut header, 480 + index * 8, value, order);
        }
        // The parser, not the fixture, must establish cross-vdev allocation.
        assert!(BlockPointer::parse(&leader, order).unwrap().gang());
        fixture.table[512..1024].copy_from_slice(&dnode(19, 2, &leader, order));
        fixture.store(0, FIRST, &first);
        fixture.store(1, SECOND, &second);
        fixture.store(1, OTHER, &header);
        fixture.publish_graph();
        fixture.poison(2, OTHER);
        fixture.poison(0, FIRST);
        fixture.poison(3, SECOND);
        let mut objects = fixture
            .pool(&[3, 0, 2, 1], &[Fault::None; 4])
            .objects(&cx, 0, 2, 123)
            .unwrap();
        assert_eq!(objects.read(&cx, 1, 0, 1024).unwrap(), payload);
        let report = objects
            .scrub(
                &cx,
                ScrubLimits {
                    copy_bytes: Some(1 << 30),
                    ..ScrubLimits::default()
                },
            )
            .unwrap();
        assert_eq!(report.errors, 3);
        assert_eq!(report.copies_examined, 8);
        assert!(!report.is_clean());
    }
}

#[test]
fn striped_mirror_automatic_selection_preserves_explicit_config_and_replica_reads() {
    let fixture = Fixture::new([2, 2], [9, 12], Endian::Little);
    let pool = fixture.pool(&[0, 1, 2, 3], &[Fault::None; 4]);
    let cx = Cx::for_testing();
    let explicit = pool.root(&cx, 0, 2, 123).unwrap();
    let automatic = pool.import_active(&cx, Some(123)).unwrap().2;
    assert_eq!(automatic.config, explicit.config);
    assert_eq!(automatic.data, explicit.data);
    assert_eq!(automatic.member_guid, explicit.member_guid);
    let mut objects = pool.import_objects(&cx, Some(123)).unwrap();
    drop(pool);
    assert_eq!(objects.read(&cx, 1, 0, 512).unwrap(), vec![0xA5; 512]);
}

pub(in crate::reader) fn log_fixture(
    cancel: bool,
) -> (Pool, VdevConfig, [u8; 128], Vec<u8>, Vec<Reads>, u64) {
    let order = Endian::Little;
    let mut fixture = Fixture::new([2, 2], [9, 12], order);
    let identity = [7, 9, 99, 1];
    let mut raw = vec![0; 4096];
    word(&mut raw, 136, 184, order);
    word(&mut raw, 144, 0x0210_DA7A_B10C_7A11, order);
    for (index, value) in identity.into_iter().enumerate() {
        word(&mut raw, 152 + index * 8, value, order);
    }
    let digest = checksum(&raw, 7, order).unwrap();
    for (index, value) in digest.into_iter().enumerate() {
        word(&mut raw, 152 + index * 8, value, order);
    }
    let mut pointer = [0; 128];
    word(&mut pointer, 0, (1_u64 << 32) | 8, order);
    word(&mut pointer, 8, OTHER / 512, order);
    word(
        &mut pointer,
        48,
        7 | (7 << 16) | (2 << 32) | (9 << 40) | (9 << 48) | (1 << 63),
        order,
    );
    word(&mut pointer, 80, 42, order);
    for (index, value) in identity.into_iter().enumerate() {
        word(&mut pointer, 96 + index * 8, value, order);
    }
    fixture.store(1, OTHER, &raw);
    fixture.poison(2, OTHER);
    let logs = fixture.logs.clone();
    let mut faults = [Fault::None; 4];
    if cancel {
        faults[3] = Fault::Cancel(at(OTHER) as u64);
    }
    let cx = Cx::for_testing();
    let pool = fixture.pool(&[3, 1, 2, 0], &faults);
    let config = pool.root(&cx, 0, 2, 123).unwrap().config;
    let owner = pool.retain_striped_topology(&cx, &config).unwrap();
    for log in &logs {
        log.lock().unwrap().clear();
    }
    (owner, config, pointer, raw, logs, at(OTHER) as u64)
}
