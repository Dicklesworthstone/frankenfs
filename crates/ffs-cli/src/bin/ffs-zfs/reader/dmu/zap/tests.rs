use super::*;
use crate::reader::{ByteOffset, DATA_OFFSET, Endian, LABEL_BYTES, Leaf, SingleLeaf};
use ffs_block::ByteDevice;
use ffs_ondisk::zfs::checksum;
use ffs_ondisk::zfs_dmu::Dnode;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const BASE: usize = 1024;
const LENGTH: usize = 8 * 1024 * 1024;
const TABLE: u64 = DATA_OFFSET + 0x10000;
const ZAP: u64 = DATA_OFFSET + 0x15000;
const INDIRECT: u64 = DATA_OFFSET + 0x18000;
const DATASET: u64 = DATA_OFFSET + 0x20000;
type Reads = Arc<Mutex<Vec<u64>>>;

fn w16(raw: &mut [u8], at: usize, value: u16, order: Endian) {
    let bytes = match order {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    raw[at..at + 2].copy_from_slice(&bytes);
}
fn w64(raw: &mut [u8], at: usize, value: u64, order: Endian) {
    raw[at..at + 8].copy_from_slice(&order.encode(value));
}
fn pointer(
    raw: &[u8],
    at: u64,
    kind: u8,
    level: u8,
    birth: u64,
    order: Endian,
    payload: Endian,
) -> Vec<u8> {
    let mut words = [0_u64; 16];
    words[0] = raw.len() as u64 / 512;
    words[1] = (at - DATA_OFFSET) / 512;
    words[6] = (raw.len() as u64 / 512 - 1)
        | ((raw.len() as u64 / 512 - 1) << 16)
        | (2 << 32)
        | (7 << 40)
        | (u64::from(kind) << 48)
        | (u64::from(level) << 56)
        | (u64::from(payload == Endian::Little) << 63);
    words[10] = birth;
    words[12..].copy_from_slice(&checksum(raw, 7, payload).unwrap());
    words
        .into_iter()
        .flat_map(|word| order.encode(word))
        .collect()
}
fn node(kind: u8, size: usize, levels: u8, max: u64, order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = levels;
    raw[3] = 1;
    raw[7] = 1;
    w16(&mut raw, 8, (size / 512) as u16, order);
    w64(&mut raw, 16, max, order);
    raw
}

fn leaf(order: Endian, populated: bool, case: u8) -> Vec<u8> {
    let mut raw = vec![0; 512];
    w64(&mut raw, 0, 1_u64 << 63, order);
    w64(&mut raw, 16, u64::from(populated), order);
    let magic = match order {
        Endian::Little => 0x02ab_1eaf_u32.to_le_bytes(),
        Endian::Big => 0x02ab_1eaf_u32.to_be_bytes(),
    };
    raw[24..28].copy_from_slice(&magic);
    w16(&mut raw, 30, u16::from(populated), order);
    w16(&mut raw, 32, 1, order);
    raw[48..80].fill(0xFF);
    let used = if !populated {
        0
    } else if case == 11 {
        2
    } else {
        3
    };
    w16(&mut raw, 28, 18 - used, order);
    w16(&mut raw, 34, used, order);
    for i in used..18 {
        let at = 80 + usize::from(i) * 24;
        raw[at] = 253;
        w16(
            &mut raw,
            at + 22,
            if i == 17 { u16::MAX } else { i + 1 },
            order,
        );
    }
    if populated {
        // Independently fixed salted CRC64("root_dataset"), high 28 bits.
        let hash = 0xea59_a240_0000_0000_u64;
        w16(&mut raw, 48 + ((hash >> 59) as usize & 15) * 2, 0, order);
        raw[80] = 252;
        raw[81] = if case == 9 { 1 } else { 8 };
        w16(&mut raw, 82, u16::MAX, order);
        w16(&mut raw, 84, 1, order);
        w16(&mut raw, 86, 13, order);
        w16(&mut raw, 88, if case == 11 { u16::MAX } else { 2 }, order);
        w16(
            &mut raw,
            90,
            if case == 10 { 2 } else { u16::from(case != 11) },
            order,
        );
        w64(&mut raw, 96, hash, order);
        raw[104] = 251;
        raw[105..118].copy_from_slice(b"root_dataset\0");
        w16(&mut raw, 126, u16::MAX, order);
        if case != 11 {
            raw[128] = 251;
            if case == 9 {
                raw[129] = 2;
            } else {
                raw[129..137].copy_from_slice(&2_u64.to_be_bytes());
            }
            if case == 10 {
                raw[137..145].copy_from_slice(&3_u64.to_be_bytes());
            }
            w16(&mut raw, 150, u16::MAX, order);
        }
        match case {
            2 => w64(&mut raw, 16, 0, order),
            3 => raw[105] = b'X',
            4 => raw[48..80].fill(0xFF),
            _ => {}
        }
    }
    raw
}

/// Small native-layout graph, deliberately not a claim of an OpenZFS-created pool.
fn graph(order: Endian, layout: u8, case: u8, reads: Reads, failure: Option<u64>) -> (Leaf, Dnode) {
    let other = if order == Endian::Little {
        Endian::Big
    } else {
        Endian::Little
    };
    let count = match layout {
        0 => 3,
        1 => 4,
        _ => 6,
    };
    let mut blocks = vec![vec![0; 512]; count];
    for (at, value) in [
        (0, FAT_TAG),
        (8, 0x0002_f52a_b2ab),
        (32, if layout == 0 { 5 } else { 6 }),
        (56, count as u64),
        (64, 2),
        (72, if case == 5 { 2 } else { 1 }),
        (80, 0x0123_4567_89ab_cdef),
    ] {
        w64(&mut blocks[0], at, value, order);
    }
    if layout != 0 {
        w64(&mut blocks[0], 16, 3, order);
        w64(&mut blocks[0], 24, 1, order);
    }
    if layout == 2 {
        w64(&mut blocks[0], 40, 4, order);
        w64(&mut blocks[0], 48, 1, order);
        for at in (0..512).step_by(8) {
            w64(&mut blocks[4], at, 1, other);
            w64(&mut blocks[5], at, 2, order);
        }
        if case == 7 {
            w64(&mut blocks[5], 504, 1, order);
        }
    }
    for i in 0..if layout == 0 { 32 } else { 64 } {
        let target = if case == 1 {
            3
        } else if i < if layout == 0 { 16 } else { 32 } {
            1
        } else {
            2
        };
        if layout == 0 {
            w64(&mut blocks[0], 256 + i * 8, target, order);
        } else {
            w64(&mut blocks[3], i * 8, target, other);
        }
    }
    blocks[1] = leaf(other, false, case);
    blocks[2] = leaf(order, true, case);
    let mut image = vec![0; BASE + LENGTH + 512];
    image[..BASE].fill(0xA5);
    image[BASE + LENGTH..].fill(0x5A);
    let mut indirect = vec![0; 4096];
    for (i, block) in blocks.iter().enumerate() {
        let at = ZAP + (i as u64) * 512;
        let payload = if matches!(i, 1 | 3 | 4) { other } else { order };
        if case != 8 || i != 2 {
            indirect[i * 128..i * 128 + 128]
                .copy_from_slice(&pointer(block, at, 1, 0, 20, other, payload));
        }
        image[BASE + at as usize..BASE + at as usize + 512].copy_from_slice(block);
    }
    if case == 6 {
        image[BASE + ZAP as usize + 2 * 512 + 200] ^= 1;
    }
    image[BASE + INDIRECT as usize..BASE + INDIRECT as usize + 4096].copy_from_slice(&indirect);
    let mut zap_node = node(1, 512, 2, count as u64 - 1, order);
    zap_node[64..192].copy_from_slice(&pointer(&indirect, INDIRECT, 1, 1, 30, order, other));
    let mut table = vec![0; 16384];
    table[512..1024].copy_from_slice(&zap_node);
    let mut dir = node(12, 512, 1, 0, order);
    dir[4] = 12;
    w16(&mut dir, 10, 256, order);
    w64(&mut dir, 192 + 8, 3, order);
    table[1024..1536].copy_from_slice(&dir);
    let mut root = vec![0; 1024];
    root[..512].copy_from_slice(&node(10, 16384, 1, 0, other));
    w64(&mut root, 704, 2, other);
    image[BASE + DATASET as usize..BASE + DATASET as usize + 1024].copy_from_slice(&root);
    let mut dataset = node(16, 512, 1, 0, order);
    dataset[4] = 16;
    w16(&mut dataset, 10, 320, order);
    for (at, value) in [(0, 2), (56, 5), (112, 987), (120, 4)] {
        w64(&mut dataset, 192 + at, value, order);
    }
    dataset[320..448].copy_from_slice(&pointer(&root, DATASET, 11, 0, 25, order, other));
    table[1536..2048].copy_from_slice(&dataset);
    image[BASE + TABLE as usize..BASE + TABLE as usize + 16384].copy_from_slice(&table);
    let mut meta = node(10, 16384, 1, 0, other);
    meta[64..192].copy_from_slice(&pointer(&table, TABLE, 10, 0, 40, other, order));
    let leaf = Leaf::from_device(
        &Cx::for_testing(),
        Box::new(Memory {
            image,
            reads,
            failure,
        }),
        BASE as u64,
        LENGTH as u64,
    )
    .unwrap();
    (leaf, Dnode::parse(&meta, other).unwrap())
}

struct Memory {
    image: Vec<u8>,
    reads: Reads,
    failure: Option<u64>,
}
impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 {
        self.image.len() as u64
    }
    fn read_exact_at(&self, _: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push(offset.0);
        if self.failure == Some(offset.0) {
            return Err(FfsError::Cancelled);
        }
        let at = offset.0 as usize;
        let end = at
            .checked_add(bytes.len())
            .ok_or_else(|| corrupt("test read overflow"))?;
        bytes.copy_from_slice(
            self.image
                .get(at..end)
                .ok_or_else(|| corrupt("short test image"))?,
        );
        Ok(())
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("ZAP enumeration wrote image")
    }
    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("ZAP enumeration flushed image")
    }
}
fn view(leaf: &Leaf, meta: Dnode) -> Objects<'_> {
    Objects {
        leaf,
        config: SingleLeaf {
            pool_guid: 123,
            leaf_guid: 999,
            version: 5000,
            txg: 42,
            ashift: 9,
            id: 0,
            allocated_bytes: LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES,
            read_features: Vec::new(),
        },
        txg: 43,
        root_birth: 42,
        meta,
        cache: VecDeque::new(),
        cached_bytes: 0,
    }
}

#[test]
fn native_tables_and_each_blocks_byte_order_feed_dsl_inventory() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for layout in 0..=2 {
            let reads: Reads = Arc::default();
            let (leaf, meta) = graph(order, layout, 0, Arc::clone(&reads), None);
            let mut objects = view(&leaf, meta);
            let entries = objects.zap(&cx, 1).unwrap();
            assert_eq!(
                (entries[0].name.as_slice(), entries[0].value),
                (b"root_dataset".as_slice(), 2)
            );
            assert_eq!(objects.datasets(&cx).unwrap()[0].guid, 987);
            assert_eq!(
                reads
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|at| **at == BASE as u64 + ZAP + 2 * 512)
                    .count(),
                1
            );
            let count = reads.lock().unwrap().len();
            assert_eq!(objects.zap(&cx, 1).unwrap(), entries);
            assert_eq!(reads.lock().unwrap().len(), count);
        }
    }
}

#[test]
fn bad_routes_hashes_counts_copies_and_sparse_leaves_are_errors() {
    let cx = Cx::for_testing();
    for case in 1..=8 {
        let reads: Reads = Arc::default();
        let (leaf, meta) = graph(Endian::Little, 2, case, Arc::clone(&reads), None);
        assert!(view(&leaf, meta).zap_values(&cx, 1).is_err(), "case {case}");
        if matches!(case, 1 | 7) {
            assert!(!reads.lock().unwrap().contains(&(BASE as u64 + ZAP + 512)));
        }
    }
}

#[test]
fn array_and_presence_values_are_not_silently_cast_to_object_references() {
    let cx = Cx::for_testing();
    for case in 9..=11 {
        let (leaf, meta) = graph(Endian::Big, 1, case, Arc::default(), None);
        let mut objects = view(&leaf, meta);
        let values = objects.zap_values(&cx, 1).unwrap();
        match case {
            9 => {
                assert_eq!(values[0].integer_bytes, 1);
                assert_eq!(values[0].values, [2]);
            }
            10 => assert_eq!(values[0].values, [2, 3]),
            _ => assert_eq!(values[0].values, [] as [u64; 0]),
        }
        assert!(objects.zap(&cx, 1).is_err());
        assert!(objects.datasets(&cx).is_err());
    }
}

#[test]
fn failed_late_leaf_and_copy_reads_propagate_cancellation_without_partial_map() {
    let cx = Cx::for_testing();
    for id in [2, 3, 5] {
        let reads: Reads = Arc::default();
        let offset = BASE as u64 + ZAP + id * 512;
        let (leaf, meta) = graph(Endian::Little, 2, 0, Arc::clone(&reads), Some(offset));
        assert!(matches!(
            view(&leaf, meta).zap_values(&cx, 1),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(
            reads
                .lock()
                .unwrap()
                .iter()
                .filter(|at| **at == offset)
                .count(),
            1
        );
    }
}

#[test]
fn block_work_budget_is_checked_before_even_cached_reads() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let (leaf, meta) = graph(Endian::Little, 0, 0, Arc::clone(&reads), None);
    let mut objects = view(&leaf, meta);
    objects.zap_values(&cx, 1).unwrap();
    let object = objects.load(&cx, 1).unwrap();
    reads.lock().unwrap().clear();
    let mut work = MAX_ZAP_BLOCK_BYTES;
    assert!(matches!(
        objects.zap_block(&cx, &object, 1, &mut work),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert!(reads.lock().unwrap().is_empty());
}
