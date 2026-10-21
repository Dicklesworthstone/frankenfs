//! Engine-level planted images, not native-pool or mounted interoperability.
//! Expected file bytes are specified independently of the reader. Single-data-
//! sector RAIDZ headers/fragments have identical P/Q/R and data bytes, so these
//! fixtures do not generate parity with the reconstruction code under test.

use super::*;
use crate::reader::pool::raidz::NativeMap;
use crate::reader::{Endian, Leaf, RaidzGroup, RaidzMember};
use ffs_block::ByteDevice;
use ffs_ondisk::zfs::checksum;
use ffs_types::ByteOffset;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

type Words = [u64; 16];
type Reads = Arc<Mutex<Vec<(usize, u64, usize)>>>;
const CAPACITY: u64 = 2 * 1024 * 1024;
const FIRST: u64 = 0x20000;
const SECOND: u64 = 0x40000;
const HEADER: u64 = 0x60000;
const MAGIC: u64 = 0x0210_da7a_b10c_7a11;

#[derive(Clone, Copy)]
enum Fault {
    Io,
    Cancel,
    Flip,
}

#[derive(Default)]
struct Storage {
    extents: BTreeMap<u64, Vec<u8>>,
    faults: BTreeMap<u64, Fault>,
}

struct Memory {
    id: usize,
    base: u64,
    storage: Arc<Mutex<Storage>>,
    reads: Reads,
}

impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 {
        self.base + DATA_OFFSET + CAPACITY + 2 * LABEL_BYTES
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        self.reads
            .lock()
            .unwrap()
            .push((self.id, offset.0, out.len()));
        let storage = self.storage.lock().unwrap();
        let fault = storage.faults.get(&offset.0);
        match fault {
            Some(Fault::Cancel) => return Err(FfsError::Cancelled),
            Some(Fault::Io) => return Err(FfsError::Io(std::io::Error::other("planted I/O"))),
            _ => {}
        }
        let (&start, data) = storage
            .extents
            .range(..=offset.0)
            .next_back()
            .ok_or_else(|| corrupt("test read has no planted extent"))?;
        let start = usize::try_from(offset.0 - start).unwrap();
        let bytes = data
            .get(start..start + out.len())
            .ok_or_else(|| corrupt("test read exceeds planted extent"))?;
        out.copy_from_slice(bytes);
        if matches!(fault, Some(Fault::Flip)) {
            out[0] ^= 1;
        }
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> Result<()> {
        panic!("read-only gang extraction attempted a backing write")
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        panic!("read-only gang extraction attempted backing synchronization")
    }
}

struct Fixture {
    config: VdevConfig,
    storage: Vec<Arc<Mutex<Storage>>>,
    reads: Reads,
    base: u64,
}

impl Fixture {
    fn new(parity: usize, width: usize, ashift: u8, base: u64) -> Self {
        let group = (parity != 0).then(|| RaidzGroup {
            parity,
            members: (0..width)
                .map(|id| RaidzMember {
                    supplied_index: width - 1 - id,
                    guid: 100 + id as u64,
                    ashift,
                    allocated_bytes: CAPACITY,
                })
                .collect(),
        });
        Self {
            config: VdevConfig {
                pool_guid: 1,
                top_guid: 2,
                version: 5000,
                txg: 5,
                ashift,
                id: 0,
                allocated_bytes: CAPACITY * if parity == 0 { 1 } else { width as u64 },
                read_features: Vec::new(),
                raidz_members: group,
            },
            storage: (0..width).map(|_| Arc::default()).collect(),
            reads: Arc::default(),
            base,
        }
    }

    fn pool(&self) -> Pool {
        // Reverse the supplied order to exercise native-child-ID routing.
        let leaves = (0..self.storage.len())
            .rev()
            .map(|id| {
                Leaf::from_device(
                    &Cx::for_testing(),
                    Box::new(Memory {
                        id,
                        base: self.base,
                        storage: Arc::clone(&self.storage[id]),
                        reads: Arc::clone(&self.reads),
                    }),
                    self.base,
                    DATA_OFFSET + CAPACITY + 2 * LABEL_BYTES,
                )
                .unwrap()
            })
            .collect();
        Pool::from_leaves(leaves).unwrap()
    }

    fn address(&self, offset: u64) -> u64 {
        self.base + DATA_OFFSET + offset
    }

    fn read(&self, words: &Words, container: Endian) -> Result<BlockRead> {
        self.pool()
            .read_block(&Cx::for_testing(), &self.config, &pointer(words, container))
    }

    fn store(&self, id: usize, offset: u64, bytes: Vec<u8>) {
        self.storage[id]
            .lock()
            .unwrap()
            .extents
            .insert(self.address(offset), bytes);
    }

    fn fault(&self, id: usize, offset: u64, fault: Fault) {
        self.storage[id]
            .lock()
            .unwrap()
            .faults
            .insert(self.address(offset), fault);
    }

    fn install(&self, offset: u64, bytes: &[u8]) {
        assert_eq!(bytes.len(), 512);
        if let Some(group) = &self.config.raidz_members {
            let map = NativeMap::new(
                offset,
                512,
                self.config.ashift,
                group.members.len(),
                group.parity,
            )
            .unwrap();
            assert_eq!(
                map.columns()
                    .iter()
                    .filter(|c| c.data_offset.is_some())
                    .count(),
                1,
            );
            for column in map.columns().iter().filter(|column| column.bytes != 0) {
                let mut padded = vec![0; column.bytes];
                padded[..512].copy_from_slice(bytes);
                self.store(column.child_id, column.offset, padded);
            }
        } else {
            for id in 0..self.storage.len() {
                self.store(id, offset, bytes.to_vec());
            }
        }
    }

    fn seed_pair(&self, order: Endian, offset: u64, physical: &[u8]) -> (Words, [u8; 512]) {
        assert_eq!(physical.len(), 1024);
        let allocation = header_allocation(&self.config).unwrap();
        let children = [
            member(&physical[..512], FIRST, allocation, order),
            member(&physical[512..], SECOND, allocation, order),
        ];
        let (mut root, header) = gang(physical, &children, offset, allocation, order);
        root[6] |= 19_u64 << 48;
        root[9] = 5;
        root[10] = 7;
        self.install(FIRST, &physical[..512]);
        self.install(SECOND, &physical[512..]);
        self.install(offset, &header);
        (root, header)
    }
}

fn encode(words: &Words, order: Endian) -> [u8; 128] {
    let mut raw = [0; 128];
    for (index, word) in words.iter().enumerate() {
        raw[index * 8..index * 8 + 8].copy_from_slice(&order.encode(*word));
    }
    raw
}

fn pointer(words: &Words, container: Endian) -> BlockPointer {
    BlockPointer::parse(&encode(words, container), container).unwrap()
}

fn member(data: &[u8], offset: u64, allocation: u64, order: Endian) -> Words {
    let sectors = data.len() as u64 / 512;
    let mut words = [0; 16];
    words[0] = allocation / 512;
    words[1] = offset / 512;
    words[6] = (sectors - 1)
        | ((sectors - 1) << 16)
        | (2_u64 << 32)
        | (8_u64 << 40)
        | (u64::from(order == Endian::Little) << 63);
    words[10] = 5;
    words[12..].copy_from_slice(&checksum(data, 8, order).unwrap());
    words
}

fn gang(
    physical: &[u8],
    children: &[Words],
    offset: u64,
    allocation: u64,
    order: Endian,
) -> (Words, [u8; 512]) {
    let total = allocation
        + children
            .iter()
            .map(|words| (words[0] & 0x00ff_ffff) * 512)
            .sum::<u64>();
    let mut words = member(physical, offset, total, order);
    words[1] |= 1_u64 << 63;
    (words, header(&words, children, order))
}

fn header(parent: &Words, children: &[Words], order: Endian) -> [u8; 512] {
    let mut raw = [0; 512];
    for (index, child) in children.iter().enumerate() {
        raw[index * 128..index * 128 + 128].copy_from_slice(&encode(child, order));
    }
    raw[472..480].copy_from_slice(&order.encode(MAGIC));
    let birth = if parent[9] == 0 {
        parent[10]
    } else {
        parent[9]
    };
    let verifier = [
        (parent[0] >> 32) & 0x00ff_ffff,
        (parent[1] & 0x7fff_ffff_ffff_ffff) * 512,
        birth,
        0,
    ];
    for (index, word) in verifier.iter().enumerate() {
        raw[480 + index * 8..488 + index * 8].copy_from_slice(&order.encode(*word));
    }
    let sum = checksum(&raw, 8, Endian::Big).unwrap();
    for (index, word) in sum.iter().enumerate() {
        raw[480 + index * 8..488 + index * 8].copy_from_slice(&order.encode(*word));
    }
    raw
}

fn payload() -> Vec<u8> {
    [vec![0x11; 512], vec![0x22; 512]].concat()
}

#[test]
fn leaf_and_pool_paths_extract_gang_bytes_in_both_orders_and_bounded_partitions() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for ashift in [9, 12, 16] {
            let image = Fixture::new(0, 1, ashift, 1024 * 1024);
            let physical = payload();
            let (root, _) = image.seed_pair(order, HEADER, &physical);
            let bp = pointer(&root, order);
            let pool = image.pool();
            assert_eq!(
                pool.read_block(&cx, &image.config, &bp).unwrap().bytes,
                physical
            );
            let leaf = pool.standalone_leaf().unwrap();
            let (bytes, offset, copy) = leaf.read_block(&cx, &image.config, &bp).unwrap();
            assert_eq!(bytes, physical);
            assert_eq!((offset, copy), (DATA_OFFSET + HEADER, 0));
            assert!(
                image
                    .reads
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|(_, at, length)| { *at >= image.base + DATA_OFFSET && *length == 512 })
            );
        }
    }
}

#[test]
fn header_at_last_sector_does_not_treat_aggregate_asize_as_contiguous() {
    let image = Fixture::new(0, 1, 9, 0);
    let expected = payload();
    let offset = CAPACITY - 512;
    let (root, _) = image.seed_pair(Endian::Little, offset, &expected);
    assert!(offset + (root[0] & 0x00ff_ffff) * 512 > CAPACITY);
    let result = image.read(&root, Endian::Little);
    assert_eq!(result.unwrap().bytes, expected);
}

#[test]
fn extra_header_copy_uses_dva_zero_verifier_and_recovers_bad_first_header() {
    let image = Fixture::new(0, 1, 9, 4096);
    let expected = payload();
    let (mut root, header) = image.seed_pair(Endian::Little, HEADER, &expected);
    root[2] = 1;
    root[3] = (1_u64 << 63) | (0x18000 / 512);
    image.install(0x18000, &header);
    image.fault(0, HEADER, Fault::Flip);
    let block = image.read(&root, Endian::Big).unwrap();
    assert_eq!(block.bytes, expected);
    assert_eq!(block.copy_index, 1);
    assert_eq!(block.physical_offset, DATA_OFFSET + 0x18000);
}

#[test]
fn raidz_header_replicas_keep_per_copy_allocations_during_fallback() {
    for parity in 1..=3 {
        let width = parity + 2;
        let image = Fixture::new(parity, width, 12, 4096);
        let expected = payload();
        let (mut root, header) = image.seed_pair(Endian::Little, HEADER, &expected);
        let allocation = header_allocation(&image.config).unwrap();
        root[2] = allocation / 512;
        root[3] = (1_u64 << 63) | (0x18000 / 512);
        image.install(0x18000, &header);
        // Lose the first header's entire stripe. The second DVA accounts only
        // for its header, while DVA zero also accounts for the two fragments.
        let map = NativeMap::new(HEADER, 512, 12, width, parity).unwrap();
        for column in map.columns() {
            image.fault(column.child_id, column.offset, Fault::Io);
        }
        let block = image.read(&root, Endian::Little).unwrap();
        assert_eq!(block.bytes, expected);
        assert_eq!(block.copy_index, 1);
        assert_eq!(block.raidz.unwrap().allocated_bytes, allocation);

        // A malformed later header copy must fail admission before any I/O,
        // even though the first copy retains a valid aggregate allocation.
        image.reads.lock().unwrap().clear();
        root[2] -= 1;
        assert!(image.read(&root, Endian::Little).is_err());
        assert!(image.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn mirror_header_and_fragment_retries_keep_native_membership() {
    let image = Fixture::new(0, 2, 9, 0);
    let expected = payload();
    let (root, _) = image.seed_pair(Endian::Big, HEADER, &expected);
    // Supplied member zero is native ID one. Its header and first fragment
    // fail independently; neither failure permits unchecked bytes to escape.
    image.fault(1, HEADER, Fault::Flip);
    image.fault(1, FIRST, Fault::Io);
    let block = image.read(&root, Endian::Big).unwrap();
    assert_eq!(block.bytes, expected);
    assert_eq!(block.member_index, 1);
    assert!(
        image
            .reads
            .lock()
            .unwrap()
            .iter()
            .any(|(id, at, _)| { *id == 0 && *at == image.address(FIRST) })
    );
}

#[test]
fn raidz_one_two_and_three_recover_headers_using_embedded_not_payload_checksums() {
    for parity in 1..=3 {
        for width in parity + 1..=8 {
            for ashift in [9, 12] {
                let image = Fixture::new(parity, width, ashift, 1024 * 1024);
                let expected = payload();
                let (root, _) = image.seed_pair(Endian::Little, HEADER, &expected);
                let map = NativeMap::new(HEADER, 512, ashift, width, parity).unwrap();
                let data = &map.columns()[parity];
                image.fault(data.child_id, data.offset, Fault::Flip);
                // With one data sector every native parity equals the data.
                // RAIDZ2/3 can also avoid bad P while using Q or R.
                if parity >= 2 {
                    let p = &map.columns()[0];
                    image.fault(p.child_id, p.offset, Fault::Io);
                }
                if parity == 3 {
                    let q = &map.columns()[1];
                    image.fault(q.child_id, q.offset, Fault::Io);
                }
                let block = image.read(&root, Endian::Little).unwrap();
                assert_eq!(block.bytes, expected);
                let info = block.raidz.unwrap();
                assert!(info.parity_read);
                assert_eq!(info.reconstructed_children, vec![data.child_id]);
                assert_eq!(info.allocated_bytes, map.allocated_bytes());
            }
        }
    }
}

#[test]
fn corrupt_gang_fragment_uses_existing_raidz_recovery_before_leader_verification() {
    let image = Fixture::new(2, 5, 9, 0);
    let expected = payload();
    let (root, _) = image.seed_pair(Endian::Big, HEADER, &expected);
    let map = NativeMap::new(FIRST, 512, 9, 5, 2).unwrap();
    let data = &map.columns()[2];
    image.fault(data.child_id, data.offset, Fault::Flip);
    let block = image.read(&root, Endian::Big).unwrap();
    assert_eq!(block.bytes, expected);
    assert!(!block.raidz.unwrap().parity_read); // Only the header's provenance.
}

#[test]
fn raidz_header_at_allocation_end_bounds_only_the_native_header_map() {
    for parity in 1..=3 {
        let image = Fixture::new(parity, parity + 2, 9, 0);
        let allocation = header_allocation(&image.config).unwrap();
        let offset = image.config.allocated_bytes - allocation;
        let expected = payload();
        let (root, _) = image.seed_pair(Endian::Little, offset, &expected);
        assert!(offset + (root[0] & 0x00ff_ffff) * 512 > image.config.allocated_bytes);
        assert_eq!(image.read(&root, Endian::Little).unwrap().bytes, expected);
    }
}

#[test]
fn raidz_rejects_invalid_later_header_copy_before_reading_a_good_first_copy() {
    for case in 0..3 {
        let image = Fixture::new(2, 5, 9, 0);
        let (mut root, _) = image.seed_pair(Endian::Little, HEADER, &payload());
        root[2] = 3;
        root[3] = (1_u64 << 63) | (0x18000 / 512);
        match case {
            0 => root[2] |= 1_u64 << 32,
            1 => root[3] = (1_u64 << 63) | (image.config.allocated_bytes / 512),
            _ => root[3] &= !(1_u64 << 63),
        }
        assert!(image.read(&root, Endian::Little).is_err());
        assert!(image.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn cancelled_raidz_header_does_not_attempt_parity_or_children() {
    for parity in 1..=3 {
        let image = Fixture::new(parity, parity + 2, 9, 0);
        let (root, _) = image.seed_pair(Endian::Little, HEADER, &payload());
        let map = NativeMap::new(HEADER, 512, 9, parity + 2, parity).unwrap();
        let data = &map.columns()[parity];
        image.fault(data.child_id, data.offset, Fault::Cancel);
        assert!(matches!(
            image.read(&root, Endian::Little),
            Err(FfsError::Cancelled)
        ));
        let reads = image.reads.lock().unwrap();
        assert_eq!(
            reads.as_slice(),
            &[(data.child_id, image.address(data.offset), 512)]
        );
    }
}

#[test]
fn leader_checksum_is_required_even_when_header_and_all_children_verify() {
    let image = Fixture::new(0, 1, 9, 0);
    let (mut root, _) = image.seed_pair(Endian::Little, HEADER, &payload());
    root[12] ^= 1;
    let result = image.read(&root, Endian::Little);
    assert!(matches!(result, Err(FfsError::Corruption { .. })));
    assert_eq!(image.reads.lock().unwrap().len(), 3);
}

#[test]
fn later_fragment_failure_never_returns_a_successful_prefix() {
    let image = Fixture::new(0, 1, 9, 0);
    let (root, _) = image.seed_pair(Endian::Little, HEADER, &payload());
    image.fault(0, SECOND, Fault::Flip);
    let result = image.read(&root, Endian::Little);
    assert!(result.is_err());
    let reads = image.reads.lock().unwrap();
    assert_eq!(reads.len(), 3);
    assert_eq!(reads[1].1, image.address(FIRST));
    assert_eq!(reads[2].1, image.address(SECOND));
}

#[test]
fn compressed_leader_decodes_only_after_complete_physical_assembly() {
    let image = Fixture::new(0, 1, 9, 0);
    let mut physical = vec![0x77; 1024];
    physical[..10].fill(255); // Ten native ZLE runs of 192 zeroes.
    physical[10] = 191; // 128 more: the complete logical 2048 bytes.
    let (mut root, _) = image.seed_pair(Endian::Little, HEADER, &physical);
    root[6] = (root[6] & !(0xffff | (0x7f_u64 << 32))) | 3 | (14_u64 << 32);
    let block = image.read(&root, Endian::Little).unwrap();
    assert_eq!(block.bytes, vec![0; 2048]);
    // A shorter logical size cannot turn an overlong run into a short success.
    root[6] = (root[6] & !0xffff) | 1;
    assert!(image.read(&root, Endian::Little).is_err());
}

#[test]
fn nested_gang_checks_interior_checksum_and_does_not_reinterpret_dmu_type() {
    for bad_interior in [false, true] {
        let image = Fixture::new(0, 1, 9, 0);
        let first = vec![0x11; 512];
        let second = vec![0x22; 512];
        let third = vec![0x33; 512];
        let children = [
            member(&first, FIRST, 512, Endian::Little),
            member(&second, SECOND, 512, Endian::Little),
        ];
        let (mut interior, inner_header) =
            gang(&payload(), &children, 0x18000, 512, Endian::Little);
        if bad_interior {
            interior[12] ^= 1;
        }
        let tail = member(&third, 0xc000, 512, Endian::Little);
        let expected = [first.clone(), second.clone(), third.clone()].concat();
        let (mut root, root_header) =
            gang(&expected, &[interior, tail], HEADER, 512, Endian::Little);
        root[6] |= (19_u64 << 48) | (1_u64 << 56);
        image.install(FIRST, &first);
        image.install(SECOND, &second);
        image.install(0xc000, &third);
        image.install(0x18000, &inner_header);
        image.install(HEADER, &root_header);
        let result = image.read(&root, Endian::Little);
        if bad_interior {
            assert!(result.is_err());
            assert!(
                !image
                    .reads
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(_, at, _)| { *at == image.address(0xc000) })
            );
        } else {
            assert_eq!(result.unwrap().bytes, expected);
        }
    }
}

#[test]
fn cancellation_stops_header_replica_and_fragment_retries() {
    for at in [HEADER, FIRST] {
        let image = Fixture::new(0, 2, 9, 0);
        let (root, _) = image.seed_pair(Endian::Little, HEADER, &payload());
        image.fault(1, at, Fault::Cancel);
        let result = image.read(&root, Endian::Little);
        assert!(matches!(result, Err(FfsError::Cancelled)));
        let reads = image.reads.lock().unwrap();
        assert_eq!(reads.last().unwrap().1, image.address(at));
        assert!(reads.iter().all(|(id, _, _)| *id == 1));
        assert_eq!(reads.len(), if at == HEADER { 1 } else { 2 });
    }
}

#[test]
fn invalid_later_dva_and_insufficient_tree_allocation_fail_before_io() {
    for case in 0..4 {
        let image = Fixture::new(0, 1, 9, 0);
        let (mut root, _) = image.seed_pair(Endian::Little, HEADER, &payload());
        root[2] = 1;
        root[3] = (1_u64 << 63) | (0x18000 / 512);
        match case {
            0 => root[2] |= 1_u64 << 32,
            1 => root[3] = (1_u64 << 63) | (CAPACITY / 512),
            2 => root[3] &= !(1_u64 << 63),
            _ => root[0] = 2,
        }
        assert!(image.read(&root, Endian::Little).is_err());
        assert!(image.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn all_bad_headers_fail_without_reading_children() {
    let image = Fixture::new(0, 2, 9, 0);
    let (root, _) = image.seed_pair(Endian::Little, HEADER, &payload());
    image.fault(0, HEADER, Fault::Flip);
    image.fault(1, HEADER, Fault::Flip);
    assert!(image.read(&root, Endian::Little).is_err());
    let reads = image.reads.lock().unwrap();
    assert_eq!(reads.len(), 2);
    assert!(reads.iter().all(|(_, at, _)| *at == image.address(HEADER)));
}

#[test]
fn traversal_limits_and_active_header_identity_fail_before_io() {
    let image = Fixture::new(0, 1, 9, 0);
    let (root, _) = image.seed_pair(Endian::Little, HEADER, &payload());
    let bp = pointer(&root, Endian::Little);
    let pool = image.pool();
    let mut destination = [0; 1024];
    let mut budget = Budget::default();
    assert!(
        pool.expand_gang(
            &Cx::for_testing(),
            &image.config,
            &bp,
            &mut destination,
            MAX_GANG_DEPTH,
            &mut budget,
        )
        .is_err()
    );
    budget.active.insert((0, HEADER));
    assert!(
        pool.expand_gang(
            &Cx::for_testing(),
            &image.config,
            &bp,
            &mut destination,
            0,
            &mut budget,
        )
        .is_err()
    );
    assert!(image.reads.lock().unwrap().is_empty());
    let mut nodes = Budget {
        nodes: MAX_GANG_NODES,
        ..Budget::default()
    };
    assert!(nodes.visit(512).is_err());
    let mut work = Budget {
        work_bytes: MAX_GANG_WORK_BYTES,
        ..Budget::default()
    };
    assert!(work.visit(512).is_err());
}

#[test]
fn repeated_verified_fragment_allocations_fail_before_payload_io_in_every_topology() {
    for order in [Endian::Little, Endian::Big] {
        for parity in 0..=3 {
            let image = Fixture::new(parity, if parity == 0 { 1 } else { parity + 2 }, 9, 4096);
            let allocation = header_allocation(&image.config).unwrap();
            let data = vec![0x71; 512];
            let child = member(&data, FIRST, allocation, order);
            // All checksums and exact native ASIZE sums are valid. Reusing one
            // physical allocation twice must still invalidate the whole tree.
            let physical = [data.clone(), data.clone()].concat();
            let (root, raw) = gang(&physical, &[child, child], HEADER, allocation, order);
            assert!(GangHeader::parse(&raw, &pointer(&root, order), &[allocation]).is_ok());
            image.install(FIRST, &data);
            image.install(HEADER, &raw);
            let error = image.read(&root, order).err().expect("overlap must fail");
            assert!(error.to_string().contains("overlaps"));
            let payload_offset = if parity == 0 {
                FIRST
            } else {
                NativeMap::new(FIRST, 512, 9, parity + 2, parity)
                    .unwrap()
                    .columns()[parity]
                    .offset
            };
            assert!(
                !image
                    .reads
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(_, at, _)| { *at == image.address(payload_offset) })
            );
        }
    }
}

#[test]
fn partial_header_and_replica_allocation_overlaps_are_rejected_before_payloads() {
    for case in 0..3 {
        let image = Fixture::new(0, 1, 9, 0);
        let first_data = vec![0x39; 1024];
        let second_data = vec![0x39; 512];
        let first = member(&first_data, FIRST, 1024, Endian::Little);
        let second_offset = if case == 1 { HEADER } else { FIRST + 512 };
        let second = member(&second_data, second_offset, 512, Endian::Little);
        let physical = [first_data.clone(), second_data.clone()].concat();
        let (mut root, mut raw) = gang(&physical, &[first, second], HEADER, 512, Endian::Little);
        if case == 2 {
            // A valid first header cannot conceal a header-only replica that
            // occupies bytes already claimed by the first ordinary fragment.
            let second = member(&second_data, SECOND, 512, Endian::Little);
            root[2] = 1;
            root[3] = (1_u64 << 63) | (FIRST / 512);
            raw = header(&root, &[first, second], Endian::Little);
        }
        image.store(0, FIRST, first_data);
        image.install(SECOND, &second_data);
        image.install(HEADER, &raw);
        let error = image
            .read(&root, Endian::Little)
            .err()
            .expect("overlap must fail");
        assert!(
            error.to_string().contains("overlaps"),
            "case {case}: {error}"
        );
        assert_eq!(
            image.reads.lock().unwrap().as_slice(),
            &[(0, image.address(HEADER), 512)]
        );
    }
}

#[test]
fn all_later_child_mappings_and_nested_headers_are_admitted_before_early_payloads() {
    for case in 0..4 {
        let image = Fixture::new(0, 1, 9, 0);
        let first_data = vec![0x18; 512];
        let tail_data = vec![0x27; 1024];
        let first = member(&first_data, FIRST, 512, Endian::Little);
        let mut children = [
            member(&tail_data[..512], SECOND, 512, Endian::Little),
            member(&tail_data[512..], 0xc000, 512, Endian::Little),
        ];
        let (nested, nested_raw) = gang(&tail_data, &children, 0x18000, 512, Endian::Little);
        let later = match case {
            0 => {
                children[0][0] |= 1_u64 << 32;
                children[0]
            }
            1 => {
                children[0][1] = CAPACITY / 512;
                children[0]
            }
            _ => nested,
        };
        let physical = if case < 2 {
            [first_data.clone(), tail_data[..512].to_vec()].concat()
        } else {
            [first_data.clone(), tail_data.clone()].concat()
        };
        let (root, raw) = gang(&physical, &[first, later], HEADER, 512, Endian::Little);
        image.install(FIRST, &first_data);
        image.install(SECOND, &tail_data[..512]);
        image.install(0xc000, &tail_data[512..]);
        image.install(0x18000, &nested_raw);
        image.install(HEADER, &raw);
        if case >= 2 {
            image.fault(
                0,
                0x18000,
                if case == 2 {
                    Fault::Flip
                } else {
                    Fault::Cancel
                },
            );
        }
        let result = image.read(&root, Endian::Little);
        if case == 3 {
            assert!(matches!(result, Err(FfsError::Cancelled)));
        } else {
            assert!(result.is_err());
        }
        assert!(!image.reads.lock().unwrap().iter().any(|(_, at, _)| {
            [FIRST, SECOND, 0xc000]
                .iter()
                .any(|offset| *at == image.address(*offset))
        }));
    }
}

#[test]
fn allocated_work_budget_counts_ditto_copies_and_every_mirror_member_before_io() {
    for (width, copies, bytes_per_copy) in [
        (1, 1, MAX_GANG_ALLOCATED_BYTES + 512),
        (1, 2, MAX_GANG_ALLOCATED_BYTES / 2 + 512),
        (2, 1, MAX_GANG_ALLOCATED_BYTES / 2 + 512),
        (8, 2, MAX_GANG_ALLOCATED_BYTES / 16 + 512),
    ] {
        let image = Fixture::new(0, width, 9, 0);
        let (mut root, _) = image.seed_pair(Endian::Little, HEADER, &payload());
        root[0] = bytes_per_copy / 512;
        if copies == 2 {
            root[2] = bytes_per_copy / 512;
            root[3] = (1_u64 << 63) | (0x18000 / 512);
        }
        let error = image
            .read(&root, Endian::Little)
            .err()
            .expect("allocated budget must fail");
        assert!(matches!(error, FfsError::UnsupportedFeature(_)));
        assert!(error.to_string().contains("allocated read budget"));
        assert!(image.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn real_depth_boundary_is_admitted_before_any_fragment_read_and_headers_are_not_reread() {
    for depth in [MAX_GANG_DEPTH, MAX_GANG_DEPTH + 1] {
        let image = Fixture::new(0, 1, 9, 0);
        let data = vec![0x52; 512];
        let mut physical = data.clone();
        let mut root = member(&data, FIRST, 512, Endian::Little);
        image.install(FIRST, &data);
        let mut leaves = vec![FIRST];
        let mut headers = Vec::new();
        for index in 0..depth {
            let leaf_offset = FIRST + (index as u64 + 1) * 512;
            let header_offset = 0x80000 + index as u64 * 512;
            let leaf = member(&data, leaf_offset, 512, Endian::Little);
            physical.extend_from_slice(&data);
            let (parent, raw) = gang(&physical, &[leaf, root], header_offset, 512, Endian::Little);
            image.install(leaf_offset, &data);
            image.install(header_offset, &raw);
            leaves.push(leaf_offset);
            headers.push(header_offset);
            root = parent;
        }
        let result = image.read(&root, Endian::Little);
        let reads = image.reads.lock().unwrap();
        if depth == MAX_GANG_DEPTH {
            assert_eq!(result.unwrap().bytes, physical);
            assert_eq!(reads.len(), headers.len() + leaves.len());
            assert!(
                reads[..headers.len()].iter().all(|(_, at, _)| {
                    headers.iter().any(|offset| *at == image.address(*offset))
                })
            );
            for offset in headers {
                assert_eq!(
                    reads
                        .iter()
                        .filter(|(_, at, _)| *at == image.address(offset))
                        .count(),
                    1
                );
            }
        } else {
            assert!(matches!(result, Err(FfsError::UnsupportedFeature(_))));
            assert!(
                !reads.iter().any(|(_, at, _)| {
                    leaves.iter().any(|offset| *at == image.address(*offset))
                })
            );
        }
    }
}
