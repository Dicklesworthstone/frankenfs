//! Constructed native-layout and no-write tests; not an OpenZFS image oracle.

use super::*;
use crate::reader::{Endian, Leaf, Pool, RaidzMember, VdevConfig};
use ffs_block::ByteDevice;
use ffs_ondisk::zfs::{LABEL_BYTES, checksum};
use ffs_ondisk::zfs_dmu::{DNODE_BLOCK_BYTES, Dnode};
use ffs_types::ByteOffset;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

const LENGTH: u64 = 8 * 1024 * 1024;
const BASE: u64 = 4096;
const HEADER: u64 = 0x40000;
const TABLE: u64 = 0x80000;
const FIRST: u64 = 0x0010_0000;
const SECOND: u64 = 0x0014_0000;
const THIRD: u64 = 0x0018_0000;
const FOURTH: u64 = 0x001c_0000;
const LEFT_HEADER: u64 = 0x0020_0000;
const RIGHT_HEADER: u64 = 0x0024_0000;
const EXTRA_HEADER: u64 = 0x0028_0000;
const DECOY: u64 = 0x002c_0000;

type RawPointer = [u8; 128];
type ReadLog = Arc<Mutex<Vec<(usize, u64, usize)>>>;

#[derive(Clone, Copy)]
enum Fault {
    Io,
    Cancel,
}

#[derive(Default)]
struct State {
    extents: BTreeMap<u64, Vec<u8>>,
    faults: BTreeMap<u64, Fault>,
}

struct Memory {
    id: usize,
    state: Arc<Mutex<State>>,
    reads: ReadLog,
}

impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 {
        BASE + LENGTH
    }

    fn read_exact_at(&self, _: &Cx, at: ByteOffset, out: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push((self.id, at.0, out.len()));
        let state = self.state.lock().unwrap();
        match state.faults.get(&at.0) {
            Some(Fault::Cancel) => return Err(FfsError::Cancelled),
            Some(Fault::Io) => return Err(FfsError::Io(std::io::Error::other("gang audit fault"))),
            None => (),
        }
        let (&start, bytes) = state
            .extents
            .range(..=at.0)
            .next_back()
            .ok_or_else(|| corrupt("unplanted gang-audit read"))?;
        let start = usize::try_from(at.0 - start).unwrap();
        let bytes = bytes
            .get(start..start + out.len())
            .ok_or_else(|| corrupt("gang-audit read outside fixture"))?;
        out.copy_from_slice(bytes);
        Ok(())
    }

    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("read-only gang audit wrote a backing image")
    }

    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("read-only gang audit flushed a backing image")
    }
}

fn word(raw: &mut [u8], at: usize, value: u64, order: Endian) {
    raw[at..at + 8].copy_from_slice(&order.encode(value));
}

fn pointer(data: &[u8], offset: u64, allocation: u64, kind: u8, order: Endian) -> RawPointer {
    let mut raw = [0; 128];
    word(&mut raw, 0, allocation / 512, order);
    word(&mut raw, 8, offset / 512, order);
    let sectors = data.len() as u64 / 512 - 1;
    word(
        &mut raw,
        48,
        sectors
            | (sectors << 16)
            | (2 << 32)
            | (7 << 40)
            | (u64::from(kind) << 48)
            | (u64::from(order == Endian::Little) << 63),
        order,
    );
    word(&mut raw, 80, 20, order);
    for (i, sum) in checksum(data, 7, order).unwrap().into_iter().enumerate() {
        word(&mut raw, 96 + i * 8, sum, order);
    }
    raw
}

fn native_header(parent: &RawPointer, children: &[RawPointer], order: Endian) -> [u8; 512] {
    let mut raw = [0; 512];
    for (index, child) in children.iter().enumerate() {
        raw[index * 128..index * 128 + 128].copy_from_slice(child);
    }
    word(&mut raw, 472, 0x0210_da7a_b10c_7a11, order);
    let address = (order.u64(parent, 8).unwrap() & !(1 << 63)) * 512;
    let birth = order.u64(parent, 72).unwrap();
    let birth = if birth == 0 {
        order.u64(parent, 80).unwrap()
    } else {
        birth
    };
    for (i, value) in [0, address, birth, 0].into_iter().enumerate() {
        word(&mut raw, 480 + i * 8, value, order);
    }
    // The native embedded header checksum is SHA-256, not the data algorithm.
    for (i, value) in checksum(&raw, 8, Endian::Big)
        .unwrap()
        .into_iter()
        .enumerate()
    {
        word(&mut raw, 480 + i * 8, value, order);
    }
    raw
}

fn dnode(kind: u8, size: usize, bp: &RawPointer, order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = 1;
    raw[3] = 1;
    raw[7] = 1;
    let sectors = (size / 512) as u16;
    let count = match order {
        Endian::Little => sectors.to_le_bytes(),
        Endian::Big => sectors.to_be_bytes(),
    };
    raw[8..10].copy_from_slice(&count);
    raw[64..192].copy_from_slice(bp);
    raw
}

fn product(mut a: u16, mut b: u16) -> u8 {
    let mut result = 0;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= 0x11d;
        }
        b >>= 1;
    }
    u8::try_from(result).unwrap()
}

struct Fixture {
    states: Vec<Arc<Mutex<State>>>,
    reads: ReadLog,
    config: VdevConfig,
    order: Endian,
}

impl Fixture {
    fn new(parity: usize, width: usize, ashift: u8, order: Endian) -> Self {
        let capacity = LENGTH - DATA_OFFSET - 2 * LABEL_BYTES;
        let allocated_bytes = capacity * if parity == 0 { 1 } else { width as u64 };
        Self {
            states: (0..width).map(|_| Arc::default()).collect(),
            reads: Arc::default(),
            order,
            config: VdevConfig {
                pool_guid: 123,
                top_guid: 777,
                version: 5000,
                txg: 40,
                ashift,
                id: 0,
                allocated_bytes,
                read_features: Vec::new(),
                raidz_members: (parity != 0).then(|| RaidzGroup {
                    parity,
                    members: (0..width)
                        .map(|child| RaidzMember {
                            supplied_index: width - child - 1,
                            guid: 1001 + child as u64,
                            ashift,
                            allocated_bytes,
                        })
                        .collect(),
                }),
            },
        }
    }

    fn store_at(&self, child: usize, offset: u64, bytes: Vec<u8>) {
        self.states[child]
            .lock()
            .unwrap()
            .extents
            .insert(BASE + DATA_OFFSET + offset, bytes);
    }

    fn store(&self, offset: u64, bytes: &[u8]) -> u64 {
        self.config.raidz_members.as_ref().map_or_else(
            || {
                for child in 0..self.states.len() {
                    self.store_at(child, offset, bytes.to_vec());
                }
                let sector = 1_u64 << self.config.ashift;
                (bytes.len() as u64).div_ceil(sector) * sector
            },
            |group| {
                let map = NativeMap::new(
                    offset,
                    bytes.len(),
                    self.config.ashift,
                    group.members.len(),
                    group.parity,
                )
                .unwrap();
                let mut padded = bytes.to_vec();
                padded.resize(map.aligned_bytes(), 0);
                let data: Vec<_> = map
                    .columns()
                    .iter()
                    .filter(|c| c.data_offset.is_some())
                    .collect();
                for column in &data {
                    let start = column.data_offset.unwrap();
                    self.store_at(
                        column.child_id,
                        column.offset,
                        padded[start..start + column.bytes].to_vec(),
                    );
                }
                for row in 0..group.parity {
                    let column = &map.columns()[row];
                    let mut parity = vec![0; column.bytes];
                    // Coefficient products independently encode P/Q/R; the runtime
                    // auditor uses Horner evaluation rather than these products.
                    for (i, source) in data.iter().enumerate() {
                        let mut coefficient = 1;
                        for _ in 0..(data.len() - i - 1) * row {
                            coefficient = product(u16::from(coefficient), 2);
                        }
                        let start = source.data_offset.unwrap();
                        for (at, value) in parity.iter_mut().take(source.bytes).enumerate() {
                            *value ^=
                                product(u16::from(padded[start + at]), u16::from(coefficient));
                        }
                    }
                    self.store_at(column.child_id, column.offset, parity);
                }
                map.allocated_bytes()
            },
        )
    }

    fn fragment(&self, offset: u64, bytes: &[u8]) -> RawPointer {
        pointer(bytes, offset, self.store(offset, bytes), 0, self.order)
    }

    fn gang(&self, offset: u64, bytes: &[u8], children: &[RawPointer], kind: u8) -> RawPointer {
        let header_bytes = (1_u64 << self.config.ashift)
            * self
                .config
                .raidz_members
                .as_ref()
                .map_or(1, |g| g.parity as u64 + 1);
        let allocated = children.iter().fold(header_bytes, |total, child| {
            total + (self.order.u64(child, 0).unwrap() & 0x00ff_ffff) * 512
        });
        let mut parent = pointer(bytes, offset, allocated, kind, self.order);
        word(&mut parent, 8, (1 << 63) | (offset / 512), self.order);
        let header = native_header(&parent, children, self.order);
        assert_eq!(self.store(offset, &header), header_bytes);
        parent
    }

    fn pair(&self) -> (RawPointer, Vec<u8>, [RawPointer; 2]) {
        let a = vec![0xa5; 512];
        let b = vec![0x5a; 512];
        let children = [self.fragment(FIRST, &a), self.fragment(SECOND, &b)];
        let expected = [a, b].concat();
        (
            self.gang(HEADER, &expected, &children, 19),
            expected,
            children,
        )
    }

    fn pool(&self) -> Pool {
        Pool::from_leaves(
            self.states
                .iter()
                .enumerate()
                .rev()
                .map(|(id, state)| {
                    Leaf::from_device(
                        &Cx::for_testing(),
                        Box::new(Memory {
                            id,
                            state: Arc::clone(state),
                            reads: Arc::clone(&self.reads),
                        }),
                        BASE,
                        LENGTH,
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap()
    }

    fn view(&self, raw: &RawPointer, size: usize) -> Objects {
        let mut table = vec![0; DNODE_BLOCK_BYTES];
        table[512..1024].copy_from_slice(&dnode(19, size, raw, self.order));
        let allocation = self.store(TABLE, &table);
        let meta_pointer = pointer(&table, TABLE, allocation, 10, self.order);
        let meta = dnode(10, DNODE_BLOCK_BYTES, &meta_pointer, self.order);
        Objects {
            pool: self.pool(),
            config: self.config.clone(),
            txg: 40,
            root_birth: 40,
            meta: Dnode::parse(&meta, self.order).unwrap(),
            cache: VecDeque::new(),
            cached_bytes: 0,
        }
    }

    fn corrupt(&self, child: usize, offset: u64) {
        self.states[child]
            .lock()
            .unwrap()
            .extents
            .get_mut(&(BASE + DATA_OFFSET + offset))
            .unwrap()[0] ^= 1;
    }

    fn fault(&self, child: usize, offset: u64, fault: Fault) {
        self.states[child]
            .lock()
            .unwrap()
            .faults
            .insert(BASE + DATA_OFFSET + offset, fault);
    }

    fn data_reads(&self, child: usize, offset: u64) -> usize {
        self.reads
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, at, _)| *id == child && *at == BASE + DATA_OFFSET + offset)
            .count()
    }
}

fn limits() -> super::super::super::ScrubLimits {
    super::super::super::ScrubLimits {
        copy_bytes: Some(1 << 32),
        ..super::super::super::ScrubLimits::default()
    }
}

#[test]
fn gang_redundancy_reaches_native_dmu_reads_and_checks_secondary_headers_and_fragments() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for ashift in [9, 12, 16] {
            for damaged in [None, Some(HEADER), Some(FIRST), Some(SECOND)] {
                let image = Fixture::new(0, 2, ashift, order);
                let (raw, expected, _) = image.pair();
                let mut view = image.view(&raw, expected.len());
                // Supplied index zero is native member one, so corrupt only
                // native member zero: ordinary reads never need that copy.
                if let Some(at) = damaged {
                    image.corrupt(0, at);
                }
                assert_eq!(view.read(&cx, 1, 0, expected.len()).unwrap(), expected);
                assert!(
                    view.scrub(&cx, super::super::super::ScrubLimits::default())
                        .unwrap()
                        .is_clean()
                );
                let before: Vec<_> = image
                    .states
                    .iter()
                    .map(|s| s.lock().unwrap().extents.clone())
                    .collect();
                let report = view.scrub(&cx, limits()).unwrap();
                assert_eq!(report.is_clean(), damaged.is_none(), "{report:?}");
                assert_eq!(report.unsupported, 0);
                assert_eq!(report.errors, u64::from(damaged.is_some()));
                assert_eq!(report.copies_examined, 8); // table + header + two fragments, two replicas
                assert_eq!(report.verified_blocks, 2); // logical table and logical gang file
                for at in [HEADER, FIRST, SECOND] {
                    assert!(image.data_reads(0, at) > 0);
                }
                for (state, before) in image.states.iter().zip(before) {
                    assert_eq!(state.lock().unwrap().extents, before);
                }
            }
        }
    }
}

#[test]
fn gang_redundancy_rejects_valid_but_divergent_headers_without_following_their_graph() {
    let cx = Cx::for_testing();
    let image = Fixture::new(0, 2, 9, Endian::Little);
    let (raw, expected, mut children) = image.pair();
    let view = image.view(&raw, expected.len());
    word(&mut children[0], 8, DECOY / 512, image.order);
    let alternate = native_header(&raw, &children, image.order);
    // A syntactically valid, correctly self-checksummed header at the SAME
    // identity is not authority to replace the admitted fragment graph.
    image.store_at(0, HEADER, alternate.to_vec());
    let report = view.scrub(&cx, limits()).unwrap();
    assert_eq!(report.errors, 1);
    assert!(!report.is_clean());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.detail.contains("fragment graph"))
    );
    for child in 0..2 {
        assert_eq!(image.data_reads(child, DECOY), 0);
    }
}

#[test]
fn gang_redundancy_checks_second_header_dvas_and_nested_fragments() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let image = Fixture::new(0, 1, 9, order);
        let physical = [
            vec![0x11; 512],
            vec![0x22; 512],
            vec![0x33; 512],
            vec![0x44; 512],
        ]
        .concat();
        let children: Vec<_> = [FIRST, SECOND, THIRD, FOURTH]
            .into_iter()
            .enumerate()
            .map(|(i, at)| image.fragment(at, &physical[i * 512..(i + 1) * 512]))
            .collect();
        let left = image.gang(LEFT_HEADER, &physical[..1024], &children[..2], 0);
        let right = image.gang(RIGHT_HEADER, &physical[1024..], &children[2..], 0);
        let mut raw = image.gang(HEADER, &physical, &[left, right], 19);
        word(&mut raw, 16, 1, order);
        word(&mut raw, 24, (1 << 63) | (EXTRA_HEADER / 512), order);
        image.store(EXTRA_HEADER, &native_header(&raw, &[left, right], order));
        let view = image.view(&raw, physical.len());
        assert!(view.scrub(&cx, limits()).unwrap().is_clean());
        image.corrupt(0, EXTRA_HEADER);
        image.corrupt(0, FOURTH);
        // The root's secondary HEADER corruption does not hide a later
        // unrecoverable fragment; normal traversal still refuses bad data.
        assert!(!view.scrub(&cx, limits()).unwrap().is_clean());
        image.corrupt(0, FOURTH); // restore fixture bytes, never a runtime write
        let report = view.scrub(&cx, limits()).unwrap();
        assert_eq!(report.errors, 1);
        assert_eq!(report.unsupported, 0);
        assert_eq!(report.copies_examined, 9); // table + 3 headers (root twice) + 4 fragments
        assert!(report.issues.iter().any(|i| i.detail.contains("DVA 1")));
    }
}

#[test]
fn gang_redundancy_reserves_complete_tree_budget_before_any_extra_io() {
    let cx = Cx::for_testing();
    let image = Fixture::new(0, 2, 9, Endian::Little);
    let (raw, expected, _) = image.pair();
    let view = image.view(&raw, expected.len());
    let bp = BlockPointer::parse(&raw, image.order).unwrap();
    let reservation = view.pool.gang_audit_work(&view.config, &bp).unwrap();
    assert_eq!(reservation, 3 * 512 * 2 * 8);
    assert!(verify(&cx, &view, &bp, reservation - 1).unwrap().is_none());
    assert!(image.reads.lock().unwrap().is_empty());
    let audit = verify(&cx, &view, &bp, reservation).unwrap().unwrap();
    assert_eq!(audit.work_bytes, reservation);
    assert_eq!(audit.copies, 6);
    assert!(audit.faults.is_empty());
}

#[test]
fn gang_redundancy_cancellation_in_unused_header_or_fragment_is_terminal() {
    let cx = Cx::for_testing();
    for at in [HEADER, FIRST, SECOND] {
        let image = Fixture::new(0, 2, 9, Endian::Little);
        let (raw, expected, _) = image.pair();
        let view = image.view(&raw, expected.len());
        image.fault(0, at, Fault::Cancel);
        assert!(
            view.scrub(&cx, super::super::super::ScrubLimits::default())
                .unwrap()
                .is_clean()
        );
        assert!(matches!(
            view.scrub(&cx, limits()),
            Err(FfsError::Cancelled)
        ));
        let reads = image.reads.lock().unwrap();
        assert_eq!(reads.last().unwrap().0, 0);
        assert_eq!(reads.last().unwrap().1, BASE + DATA_OFFSET + at);
    }
}

#[test]
fn gang_raidz_redundancy_audits_header_and_fragment_pqr_without_certifying_recovery() {
    let cx = Cx::for_testing();
    for parity in 1..=3 {
        for order in [Endian::Little, Endian::Big] {
            for ashift in [9, 12, 16] {
                for target in [HEADER, FIRST] {
                    for corrupt_data in [false, true] {
                        let image = Fixture::new(parity, parity + 2, ashift, order);
                        let (raw, expected, _) = image.pair();
                        let view = image.view(&raw, expected.len());
                        assert!(view.scrub(&cx, limits()).unwrap().is_clean());
                        let map = NativeMap::new(target, 512, ashift, parity + 2, parity).unwrap();
                        let ordinal = if corrupt_data { parity } else { parity - 1 };
                        let column = &map.columns()[ordinal];
                        image.corrupt(column.child_id, column.offset);
                        assert!(
                            view.scrub(&cx, super::super::super::ScrubLimits::default())
                                .unwrap()
                                .is_clean()
                        );
                        let report = view.scrub(&cx, limits()).unwrap();
                        assert!(!report.is_clean());
                        assert_eq!(report.errors, 1, "{report:?}");
                        assert_eq!(report.unsupported, 0);
                        assert_eq!(report.verified_blocks, 2);
                        assert_eq!(report.copies_examined, 4);
                        assert_eq!(
                            report.parity_columns_unverified,
                            if corrupt_data { parity as u64 } else { 0 }
                        );
                        assert_eq!(
                            report.parity_columns_checked,
                            (if corrupt_data { 3 } else { 4 }) * parity as u64
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn gang_manifest_failure_never_starts_fragment_audits_and_issues_remain_bounded() {
    let cx = Cx::for_testing();
    let image = Fixture::new(0, 2, 9, Endian::Little);
    let (raw, expected, _) = image.pair();
    let view = image.view(&raw, expected.len());
    for child in 0..2 {
        image.fault(child, HEADER, Fault::Io);
    }
    let bp = BlockPointer::parse(&raw, image.order).unwrap();
    let audit = verify(&cx, &view, &bp, 1 << 30).unwrap().unwrap();
    assert!(!audit.faults.is_empty());
    assert_eq!(audit.copies, 0);
    for child in 0..2 {
        assert_eq!(image.data_reads(child, FIRST), 0);
        assert_eq!(image.data_reads(child, SECOND), 0);
    }
    let mut audit = Audit::default();
    for _ in 0..1000 {
        fault(&mut audit, "planted many-copy fault", corrupt("damage")).unwrap();
    }
    assert_eq!(audit.faults.len(), MAX_POINTER_FAULTS + 1);
    assert!(
        matches!(audit.faults.last(), Some(FfsError::UnsupportedFeature(reason))
        if reason.contains("remaining copies"))
    );
    assert!(matches!(
        fault(&mut audit, "cancel after saturation", FfsError::Cancelled),
        Err(FfsError::Cancelled)
    ));
}
