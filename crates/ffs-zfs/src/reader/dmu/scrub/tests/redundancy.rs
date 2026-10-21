//! Constructed native-byte tests, not an OpenZFS or kernel-mount oracle.
use super::*;
use crate::reader::pool::raidz::NativeMap;
use crate::reader::{Pool, RaidzGroup, RaidzMember};

fn limits() -> ScrubLimits {
    ScrubLimits {
        copy_bytes: Some(1 << 30),
        ..ScrubLimits::default()
    }
}

fn leaf(storage: &Arc<Mutex<Storage>>) -> Leaf {
    Leaf::from_device(
        &Cx::for_testing(),
        Box::new(Memory(Arc::clone(storage))),
        0,
        LENGTH as u64,
    )
    .unwrap()
}

fn mirror(fixture: &Fixture) -> (Objects, Arc<Mutex<Storage>>) {
    let mut view = fixture.view();
    let other = Arc::new(Mutex::new(Storage {
        bytes: fixture.storage.lock().unwrap().bytes.clone(),
        ..Storage::default()
    }));
    view.pool = Pool::from_leaves(vec![leaf(&fixture.storage), leaf(&other)]).unwrap();
    (view, other)
}

#[test]
fn redundancy_scrub_detects_bad_secondary_copies_while_preserving_readable_traversal() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for bad in [TABLE, INDIRECT, FIRST, SPILL] {
            let fixture = Fixture::new(order);
            let (mut view, other) = mirror(&fixture);
            other.lock().unwrap().bytes[bad as usize] ^= 1;
            let before = other.lock().unwrap().bytes.clone();
            assert!(scrub(&view).is_clean());
            assert_eq!(other.lock().unwrap().reads, [] as [u64; 0]);
            // Warm unrelated caches cannot stand in for auditing the physical replicas.
            assert_eq!(view.read(&cx, 1, 0, 512).unwrap(), vec![0xA5; 512]);
            let report = view.scrub(&cx, limits()).unwrap();
            assert!(!report.is_clean());
            assert_eq!(report.errors, 1);
            assert_eq!(report.incomplete_subtrees, 0);
            assert_eq!(report.verified_blocks, 5);
            assert_eq!(report.copies_examined, 10);
            assert!(report.issues[0].detail.contains("supplied member 1"));
            assert_eq!(
                other.lock().unwrap().reads,
                [TABLE, INDIRECT, FIRST, SECOND, SPILL]
            );
            assert_eq!(other.lock().unwrap().bytes, before);
        }
    }
}

#[test]
fn redundancy_scrub_verifies_a_bad_second_dva_instead_of_first_copy_only() {
    let cx = Cx::for_testing();
    let fixture = Fixture::new(Endian::Little);
    let mut view = fixture.view();
    let second = DATA_OFFSET + 0x24000;
    {
        let mut state = fixture.storage.lock().unwrap();
        state.bytes[second as usize..second as usize + fixture.table.len()]
            .copy_from_slice(&fixture.table);
        state.bytes[second as usize] ^= 1;
    }
    let mut raw = node(10, DNODE_BLOCK_BYTES, 1, 0, fixture.order);
    let mut bp = pointer(&fixture.table, TABLE, 10, 0, 40, fixture.order);
    bp[16..24].copy_from_slice(&fixture.order.encode(fixture.table.len() as u64 / 512));
    bp[24..32].copy_from_slice(&fixture.order.encode((second - DATA_OFFSET) / 512));
    raw[64..192].copy_from_slice(&bp);
    view.meta = Dnode::parse(&raw, fixture.order).unwrap();
    assert!(scrub(&view).is_clean());
    assert!(!fixture.storage.lock().unwrap().reads.contains(&second));
    let report = view.scrub(&cx, limits()).unwrap();
    assert_eq!(report.errors, 1);
    assert_eq!(report.copies_examined, 6);
    assert!(report.issues[0].detail.contains("DVA 1"));
    assert!(fixture.storage.lock().unwrap().reads.contains(&second));
}

#[test]
fn redundancy_budget_is_reserved_before_secondary_io_and_cancellation_is_terminal() {
    let cx = Cx::for_testing();
    let fixture = Fixture::new(Endian::Little);
    let (view, other) = mirror(&fixture);
    let report = view
        .scrub(
            &cx,
            ScrubLimits {
                copy_bytes: Some(65_535),
                ..limits()
            },
        )
        .unwrap();
    assert!(!report.is_clean());
    assert_eq!(report.limit_reached, Some("physical-copy work budget"));
    assert_eq!(report.copy_work_bytes, 0);
    assert_eq!(report.copies_examined, 0);
    assert_eq!(other.lock().unwrap().reads, [] as [u64; 0]);
    assert_eq!(fixture.storage.lock().unwrap().reads, [TABLE]);
    assert!(
        view.scrub(
            &cx,
            ScrubLimits {
                copy_bytes: Some(0),
                ..limits()
            }
        )
        .is_err()
    );
    other.lock().unwrap().cancel_at = Some(TABLE);
    assert!(matches!(
        view.scrub(&cx, limits()),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(other.lock().unwrap().reads, [TABLE]);
    assert!(!fixture.storage.lock().unwrap().reads.contains(&INDIRECT));
}

fn multiply(mut a: u16, mut b: u16) -> u8 {
    let mut result = 0_u16;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= 0x11D;
        }
        b >>= 1;
    }
    u8::try_from(result).unwrap()
}

struct StripeFixture {
    states: Vec<Arc<Mutex<Storage>>>,
    parity: usize,
    order: Endian,
    locations: Vec<(u64, NativeMap)>,
}

impl StripeFixture {
    fn store(&mut self, bytes: &[u8], old: u64, kind: u8, level: u8, birth: u64) -> Vec<u8> {
        let offset = (old - DATA_OFFSET) * 4;
        let map = NativeMap::new(offset, bytes.len(), 9, self.states.len(), self.parity).unwrap();
        for column in map.columns() {
            if let Some(start) = column.data_offset {
                let at = (DATA_OFFSET + column.offset) as usize;
                self.states[column.child_id].lock().unwrap().bytes[at..at + column.bytes]
                    .copy_from_slice(&bytes[start..start + column.bytes]);
            }
        }
        // Independent coefficient-by-coefficient polynomial encoding. The
        // production verifier uses Horner evaluation, not these multiply calls.
        let data: Vec<_> = map
            .columns()
            .iter()
            .filter(|column| column.data_offset.is_some())
            .collect();
        for row in 0..self.parity {
            let parity_column = &map.columns()[row];
            let mut encoded = vec![0; parity_column.bytes];
            for (index, column) in data.iter().enumerate() {
                let mut coefficient = 1;
                for _ in 0..(data.len() - index - 1) * row {
                    coefficient = multiply(u16::from(coefficient), 2);
                }
                let start = column.data_offset.unwrap();
                for (out, &byte) in encoded.iter_mut().zip(&bytes[start..start + column.bytes]) {
                    *out ^= multiply(u16::from(byte), u16::from(coefficient));
                }
            }
            let at = (DATA_OFFSET + parity_column.offset) as usize;
            self.states[parity_column.child_id].lock().unwrap().bytes[at..at + encoded.len()]
                .copy_from_slice(&encoded);
        }
        let mut raw = pointer(bytes, DATA_OFFSET + offset, kind, level, birth, self.order);
        raw[..8].copy_from_slice(&self.order.encode(map.allocated_bytes() / 512));
        self.locations.push((old, map));
        raw
    }

    fn view(parity: usize, order: Endian) -> (Self, Objects) {
        let fixture = Fixture::new(order);
        let mut view = fixture.view();
        let width = parity + 3;
        let mut striped = Self {
            states: (0..width)
                .map(|_| {
                    Arc::new(Mutex::new(Storage {
                        bytes: vec![0; LENGTH],
                        ..Storage::default()
                    }))
                })
                .collect(),
            parity,
            order,
            locations: Vec::new(),
        };
        let mut indirect = fixture.storage.lock().unwrap().bytes
            [INDIRECT as usize..INDIRECT as usize + 4096]
            .to_vec();
        indirect[..128].copy_from_slice(&striped.store(&[0xA5; 512], FIRST, 19, 0, 20));
        indirect[256..384].copy_from_slice(&striped.store(&[0x5A; 512], SECOND, 19, 0, 20));
        let mut table = fixture.table;
        table[512 + 64..512 + 192].copy_from_slice(&striped.store(&indirect, INDIRECT, 19, 1, 30));
        table[7 * 512 + 896..7 * 512 + 1024].copy_from_slice(&striped.store(
            &[0x7E; 512],
            SPILL,
            44,
            0,
            30,
        ));
        let mut meta = node(10, DNODE_BLOCK_BYTES, 1, 0, order);
        meta[64..192].copy_from_slice(&striped.store(&table, TABLE, 10, 0, 40));
        view.meta = Dnode::parse(&meta, order).unwrap();
        view.pool = Pool::from_leaves(striped.states.iter().rev().map(leaf).collect()).unwrap();
        view.config.allocated_bytes *= width as u64;
        view.config.raidz_members = Some(RaidzGroup {
            parity,
            members: (0..width)
                .map(|index| RaidzMember {
                    supplied_index: width - index - 1,
                    guid: 1001 + index as u64,
                    ashift: 9,
                    allocated_bytes: view.config.allocated_bytes,
                })
                .collect(),
        });
        (striped, view)
    }

    fn poison(&self, key: u64, ordinal: usize) {
        let map = &self
            .locations
            .iter()
            .find(|(old, _)| *old == key)
            .unwrap()
            .1;
        let column = &map.columns()[ordinal];
        self.states[column.child_id].lock().unwrap().bytes
            [(DATA_OFFSET + column.offset) as usize] ^= 0x5B;
    }
}

#[test]
fn redundancy_scrub_finds_otherwise_unread_parity_in_all_three_native_equations() {
    let cx = Cx::for_testing();
    for parity in 1..=3 {
        for order in [Endian::Little, Endian::Big] {
            for damaged in 0..parity {
                let (fixture, view) = StripeFixture::view(parity, order);
                assert!(view.scrub(&cx, limits()).unwrap().is_clean());
                fixture.poison(TABLE, damaged);
                assert!(scrub(&view).is_clean());
                let report = view.scrub(&cx, limits()).unwrap();
                assert!(!report.is_clean());
                assert_eq!(report.errors, 1);
                assert_eq!(report.verified_blocks, 5);
                assert_eq!(report.parity_columns_checked, 5 * parity as u64);
                assert_eq!(report.parity_columns_unverified, 0);
                assert!(report.issues[0].detail.contains("parity equation"));
            }
        }
    }
}

#[test]
fn recovered_data_is_not_evidence_that_actual_columns_or_parity_are_intact() {
    let cx = Cx::for_testing();
    for parity in 1..=3 {
        let (fixture, view) = StripeFixture::view(parity, Endian::Little);
        fixture.poison(FIRST, parity);
        assert!(scrub(&view).is_clean());
        let report = view.scrub(&cx, limits()).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.errors, 1);
        assert_eq!(report.verified_blocks, 5);
        assert_eq!(report.parity_columns_unverified, parity as u64);
        assert_eq!(report.parity_columns_checked, 4 * parity as u64);
        assert!(
            report.issues[0]
                .detail
                .contains("unreconstructed RAIDZ data")
        );
    }
}

#[test]
fn readable_missing_mirror_is_not_reported_as_intact_redundancy() {
    use crate::reader::tests::mirror::{MIRROR_GUID, install_labels, native_config};

    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let fixture = Fixture::new(order);
        let mut view = fixture.view();
        let config = native_config(1001, &[1001, 1002], 9, view.config.allocated_bytes, 42);
        // This unit fixture constructs Objects directly, like its parent tests.
        // The survivor constructor validates native labels, not an uberblock.
        install_labels(
            &mut fixture.storage.lock().unwrap().bytes,
            0,
            LENGTH as u64,
            order,
            &config,
            &[0; 1024],
        );
        view.config.top_guid = MIRROR_GUID;
        view.pool =
            Pool::from_mirror_survivors(&cx, vec![leaf(&fixture.storage)], vec![1002]).unwrap();
        let before = fixture.storage.lock().unwrap().bytes.clone();
        assert!(scrub(&view).is_clean());
        let report = view.scrub(&cx, limits()).unwrap();
        assert_eq!(report.missing_native_members, 1);
        assert_eq!(report.errors, 0);
        assert_eq!(report.verified_blocks, 5);
        assert_eq!(report.copies_examined, 5);
        assert!(!report.is_clean());
        assert_eq!(fixture.storage.lock().unwrap().bytes, before);
    }
}

#[test]
fn readable_missing_raidz_never_certifies_absent_columns_and_does_not_read_them() {
    use crate::reader::tests::mirror::{MIRROR_GUID, install_labels, native_config, repack};
    use crate::reader::{NvList, Value};

    let cx = Cx::for_testing();
    for parity in 1..=3 {
        for order in [Endian::Little, Endian::Big] {
            let (fixture, mut view) = StripeFixture::view(parity, order);
            let width = fixture.states.len();
            let guids: Vec<_> = (0..width).map(|child| 1001 + child as u64).collect();
            for (child, storage) in fixture.states.iter().enumerate() {
                let raw = native_config(guids[child], &guids, 9, view.config.allocated_bytes, 42);
                let mut config = NvList::parse(&raw).unwrap();
                let Value::List(tree) = config.fields.get_mut("vdev_tree").unwrap() else {
                    panic!("native fixture tree");
                };
                tree.fields
                    .insert("type".into(), Value::String("raidz".into()));
                tree.fields
                    .insert("nparity".into(), Value::Unsigned(parity as u64));
                install_labels(
                    &mut storage.lock().unwrap().bytes,
                    0,
                    LENGTH as u64,
                    order,
                    &repack(&config),
                    &[0; 1024],
                );
            }
            let supplied: Vec<_> = (parity..width).rev().collect();
            let leaves = supplied
                .iter()
                .map(|&child| leaf(&fixture.states[child]))
                .collect();
            view.pool = Pool::from_raidz_survivors(&cx, leaves, guids[..parity].to_vec()).unwrap();
            view.config.top_guid = MIRROR_GUID;
            // The direct Objects fixture retains native child order; supplied
            // image order is reversed and absent children have no image handle.
            for (child, route) in view
                .config
                .raidz_members
                .as_mut()
                .unwrap()
                .members
                .iter_mut()
                .enumerate()
            {
                route.supplied_index = supplied
                    .iter()
                    .position(|&index| index == child)
                    .unwrap_or(usize::MAX);
            }
            assert!(scrub(&view).is_clean());
            let report = view.scrub(&cx, limits()).unwrap();
            assert_eq!(report.missing_native_members, parity);
            assert_eq!(report.verified_blocks, 5);
            assert!(!report.is_clean());
            for absent in &fixture.states[..parity] {
                assert_eq!(absent.lock().unwrap().reads, [] as [u64; 0]);
            }
        }
    }
}
