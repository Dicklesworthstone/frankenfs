use super::*;
use crate::reader::{ByteOffset, DATA_OFFSET, LABEL_BYTES};
use ffs_block::ByteDevice;
use ffs_ondisk::zfs::checksum;
use std::sync::Mutex;

const BASE: usize = 1024;
const LENGTH: usize = 8 * 1024 * 1024;
const TABLE: u64 = DATA_OFFSET + 0x10000;
const ZAP: u64 = DATA_OFFSET + 0x15000;
const INDIRECT: u64 = DATA_OFFSET + 0x18000;
const DATA_A: u64 = DATA_OFFSET + 0x1C000;
const DATA_B: u64 = DATA_OFFSET + 0x1E000;
const DATASET_ROOT: u64 = DATA_OFFSET + 0x24000;
type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

fn pointer(
    raw: &[u8],
    at: u64,
    kind: u8,
    level: u8,
    birth: u64,
    containing: Endian,
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
        .flat_map(|word| containing.encode(word))
        .collect()
}
fn word16(raw: &mut [u8], at: usize, word: u16, order: Endian) {
    let bytes = match order {
        Endian::Little => word.to_le_bytes(),
        Endian::Big => word.to_be_bytes(),
    };
    raw[at..at + 2].copy_from_slice(&bytes);
}
fn node(kind: u8, data_bytes: usize, levels: u8, max_block: u64, order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = levels;
    raw[3] = 1;
    raw[7] = 1;
    word16(&mut raw, 8, (data_bytes / 512) as u16, order);
    raw[16..24].copy_from_slice(&order.encode(max_block));
    raw
}
fn bonus(kind: u8, bytes: &[u8], order: Endian) -> Vec<u8> {
    let mut raw = node(kind, 512, 1, 0, order);
    raw[4] = kind;
    word16(&mut raw, 10, bytes.len() as u16, order);
    raw[192..192 + bytes.len()].copy_from_slice(bytes);
    raw
}
fn micro(entries: &[(&[u8], u64)], order: Endian) -> Vec<u8> {
    let mut bytes = vec![0; 512];
    bytes[..8].copy_from_slice(&order.encode((1_u64 << 63) + 3));
    for (i, (name, value)) in entries.iter().enumerate() {
        let at = 64 + i * 64;
        bytes[at..at + 8].copy_from_slice(&order.encode(*value));
        bytes[at + 14..at + 14 + name.len()].copy_from_slice(name);
    }
    bytes
}

/// Constructed native LZ4 DATA pointer for 512 repeated bytes. Only two payload
/// words are needed; their numeric byte packing is independent of either order.
pub(super) fn embedded_pointer(
    byte: u8,
    birth: u64,
    containing: Endian,
    payload: Endian,
) -> Vec<u8> {
    let mut words = [0_u64; 16];
    words[0] = u64::from_le_bytes([0, 0, 0, 12, 0x1f, byte, 1, 0]);
    words[1] = u64::from_le_bytes([255, 232, 0x50, byte, byte, byte, byte, byte]);
    words[6] = 511
        | (15 << 25)
        | (15 << 32)
        | (1 << 39)
        | (19 << 48)
        | (u64::from(payload == Endian::Little) << 63);
    words[10] = birth;
    words
        .into_iter()
        .flat_map(|word| containing.encode(word))
        .collect()
}

/// Construct the graph directly so DMU tests isolate traversal from label
/// admission, which has its own reader tests. This is NOT native-image proof.
fn graph(order: Endian, case: u8, reads: Reads, failure: Option<u64>) -> (Leaf, Dnode) {
    let other = if order == Endian::Little {
        Endian::Big
    } else {
        Endian::Little
    };
    let mut image = vec![0; BASE + LENGTH + 512];
    image[..BASE].fill(0xA5);
    image[BASE + LENGTH..].fill(0x5A);
    let mut store = |at: u64, bytes: &[u8]| {
        let at = BASE + at as usize;
        image[at..at + bytes.len()].copy_from_slice(bytes);
    };
    let a = vec![b'A'; 512];
    let b = vec![b'B'; 512];
    store(DATA_A, &a);
    store(DATA_B, &b);
    let mut indirect = vec![0; 4096];
    let mut child = if matches!(case, 17 | 18) {
        embedded_pointer_fixed_birth(b'A', other, order)
    } else {
        pointer(&a, DATA_A, 19, 0, 20, other, order)
    };
    match case {
        1 => child[48..56].copy_from_slice(&other.encode(
            (2 << 32) | (7 << 40) | (18 << 48) | (u64::from(order == Endian::Little) << 63),
        )),
        2 => child[80..88].copy_from_slice(&other.encode(35)),
        3 => child[48..56].copy_from_slice(&other.encode(
            1 | (1 << 16)
                | (2 << 32)
                | (7 << 40)
                | (19 << 48)
                | (u64::from(order == Endian::Little) << 63),
        )),
        4 => child[96] ^= 1,
        5 => child[..8].copy_from_slice(&other.encode(1 | (1 << 32))),
        6 => child[48..56].copy_from_slice(&other.encode(
            (2 << 32)
                | (7 << 40)
                | (19 << 48)
                | (1 << 56)
                | (u64::from(order == Endian::Little) << 63),
        )),
        _ => {}
    }
    if (10..=16).contains(&case) {
        child = embedded_pointer(b'E', 20, other, order);
        let prop = other.u64(&child, 48).unwrap();
        let malformed_prop = match case {
            11 => (prop & !(0x7f << 25)) | (112 << 25),
            12 => prop | (2 << 40),
            14 => (prop & !(0x7f << 32)) | (16 << 32),
            15 => (prop & !(0xff << 48)) | (20 << 48),
            16 => prop | (1 << 56),
            _ => prop,
        };
        child[48..56].copy_from_slice(&other.encode(malformed_prop));
        if case == 13 {
            child[80..88].copy_from_slice(&other.encode(35));
        }
    }
    indirect[..128].copy_from_slice(&child);
    indirect[256..384].copy_from_slice(&pointer(&b, DATA_B, 19, 0, 20, other, order));
    store(INDIRECT, &indirect);
    let mut data_node = node(19, 512, 2, 31, order);
    data_node[64..192].copy_from_slice(&pointer(&indirect, INDIRECT, 19, 1, 30, order, other));
    if case == 7 {
        data_node[64..192].fill(0);
    }
    if case == 18 {
        data_node[160] ^= 1; // Corrupt the embedded pointer's containing block checksum.
    }
    // Large dnode occupies slots 7 and 8; slot 8 deliberately looks allocated.
    data_node.resize(1024, 0);
    data_node[12] = 1;
    data_node[512..].copy_from_slice(&node(19, 512, 1, 0, order));

    let zap = micro(&[(b"root_dataset", 2)], other);
    store(ZAP, &zap);
    let mut zap_node = node(1, 512, 1, 0, order);
    zap_node[64..192].copy_from_slice(&pointer(&zap, ZAP, 1, 0, 25, order, other));
    let mut dir_bonus = vec![0; 256];
    dir_bonus[8..16].copy_from_slice(&order.encode(3));
    if case == 8 {
        dir_bonus[16..24].copy_from_slice(&order.encode(99));
    }
    let dir_node = bonus(12, &dir_bonus, order);
    let mut os = vec![0; 1024];
    os[..512].copy_from_slice(&node(10, 16384, 1, 0, other));
    os[704..712].copy_from_slice(&other.encode(2));
    store(DATASET_ROOT, &os);
    let mut ds_bonus = vec![0; 320];
    ds_bonus[..8].copy_from_slice(&order.encode(2));
    ds_bonus[56..64].copy_from_slice(&order.encode(5));
    ds_bonus[112..120].copy_from_slice(&order.encode(987));
    ds_bonus[120..128].copy_from_slice(&order.encode(if case == 9 { 1 } else { 4 }));
    ds_bonus[128..256].copy_from_slice(&pointer(&os, DATASET_ROOT, 11, 0, 25, order, other));
    let ds_node = bonus(16, &ds_bonus, order);
    let mut table = vec![0; 16384];
    table[512..1024].copy_from_slice(&zap_node);
    table[1024..1536].copy_from_slice(&dir_node);
    table[1536..2048].copy_from_slice(&ds_node);
    table[7 * 512..9 * 512].copy_from_slice(&data_node);
    store(TABLE, &table);
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

fn objects(leaf: &Leaf, meta: Dnode) -> Objects {
    Objects {
        leaf: leaf.clone(),
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
struct Memory {
    image: Vec<u8>,
    reads: Reads,
    failure: Option<u64>,
}
impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 {
        self.image.len() as u64
    }
    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push((offset.0, bytes.len()));
        if self.failure == Some(offset.0) {
            return Err(FfsError::Cancelled);
        }
        let at = offset.0 as usize;
        let end = at
            .checked_add(bytes.len())
            .ok_or_else(|| corrupt("test span overflow"))?;
        bytes.copy_from_slice(
            self.image
                .get(at..end)
                .ok_or_else(|| corrupt("short test image"))?,
        );
        Ok(())
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("DMU read wrote to image")
    }
    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("DMU read flushed image")
    }
}

#[test]
fn indirect_reads_follow_each_blocks_byte_order_and_preserve_holes() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let reads: Reads = Arc::default();
        let (leaf, meta) = graph(order, 0, Arc::clone(&reads), None);
        let mut view = objects(&leaf, meta);
        let mut expected = vec![b'A'; 2];
        expected.extend_from_slice(&[0; 512]);
        expected.extend_from_slice(&[b'B'; 512]);
        assert_eq!(view.read(&cx, 7, 510, 1026).unwrap(), expected);
        assert_eq!(view.object(&cx, 7).unwrap().slots(), 2);
        assert!(view.object(&cx, 8).is_err());
        assert!(matches!(view.object(&cx, 9), Err(FfsError::NotFound(_))));
        let count = reads.lock().unwrap().len();
        assert_eq!(view.read(&cx, 7, 510, 1026).unwrap(), expected);
        assert_eq!(reads.lock().unwrap().len(), count);
        assert_eq!(view.zap(&cx, 1).unwrap()[0].name, b"root_dataset");
        assert!(
            reads.lock().unwrap().iter().all(
                |(at, size)| *at >= BASE as u64 && *at + *size as u64 <= (BASE + LENGTH) as u64
            )
        );
    }
}
#[test]
fn typed_birth_size_and_vdev_mismatch_refuse_before_data_reads() {
    let cx = Cx::for_testing();
    for case in [1, 2, 3, 5, 6] {
        let reads: Reads = Arc::default();
        let (leaf, meta) = graph(Endian::Little, case, Arc::clone(&reads), None);
        assert!(objects(&leaf, meta).read(&cx, 7, 0, 1).is_err(), "{case}");
        assert!(
            !reads
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| *at == BASE as u64 + DATA_A)
        );
    }
}
#[test]
fn checksum_and_cancellation_fail_without_successful_partial_ranges() {
    let cx = Cx::for_testing();
    let (leaf, meta) = graph(Endian::Little, 4, Arc::default(), None);
    assert!(objects(&leaf, meta).read(&cx, 7, 0, 1536).is_err());
    let reads: Reads = Arc::default();
    let (leaf, meta) = graph(
        Endian::Little,
        0,
        Arc::clone(&reads),
        Some(BASE as u64 + DATA_B),
    );
    assert!(matches!(
        objects(&leaf, meta).read(&cx, 7, 0, 1536),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(
        reads
            .lock()
            .unwrap()
            .iter()
            .filter(|(at, _)| *at == BASE as u64 + DATA_B)
            .count(),
        1
    );
}
#[test]
fn sparse_indirect_subtrees_and_invalid_ranges_do_not_read_data() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let (leaf, meta) = graph(Endian::Little, 7, Arc::clone(&reads), None);
    let mut view = objects(&leaf, meta);
    view.object(&cx, 7).unwrap();
    reads.lock().unwrap().clear();
    assert_eq!(view.read(&cx, 7, 0, 16384).unwrap(), vec![0; 16384]);
    assert!(view.read(&cx, 7, u64::MAX, 2).is_err());
    assert!(view.read(&cx, 7, 31 * 512, 513).is_err());
    assert!(view.read(&cx, 7, 0, MAX_READ_BYTES + 1).is_err());
    assert!(reads.lock().unwrap().is_empty());
}
#[test]
fn dsl_inventory_verifies_head_root_and_parent_relationships() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let (leaf, meta) = graph(order, 0, Arc::default(), None);
        let result = objects(&leaf, meta).datasets(&cx).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            (
                result[0].directory_object,
                result[0].head_object,
                result[0].guid
            ),
            (2, 3, 987)
        );
        assert_eq!((result[0].objectset_kind, result[0].root_birth), (2, 25));
        assert_eq!(result[0].components, [] as [Vec<u8>; 0]);
    }
    for case in [8, 9] {
        let (leaf, meta) = graph(Endian::Little, case, Arc::default(), None);
        assert!(objects(&leaf, meta).datasets(&cx).is_err());
    }
}
#[test]
fn cached_block_still_requires_the_callers_type_level_and_birth() {
    let cx = Cx::for_testing();
    let (leaf, meta) = graph(Endian::Little, 0, Arc::default(), None);
    let mut view = objects(&leaf, meta);
    view.read(&cx, 7, 0, 1).unwrap();
    let bp = BlockPointer::parse(
        &pointer(
            &vec![b'A'; 512],
            DATA_A,
            19,
            0,
            20,
            Endian::Little,
            Endian::Little,
        ),
        Endian::Little,
    )
    .unwrap();
    assert!(view.checked(&cx, &bp, 18, 0, 512, 30).is_err());
    assert!(view.checked(&cx, &bp, 19, 1, 512, 30).is_err());
    assert!(view.checked(&cx, &bp, 19, 0, 512, 19).is_err());
}

#[test]
fn embedded_reads_mix_sparse_and_physical_blocks_without_inventing_dva_io() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let reads: Reads = Arc::default();
        let (leaf, meta) = graph(order, 10, Arc::clone(&reads), None);
        let mut view = objects(&leaf, meta);
        view.config
            .read_features
            .push("com.delphix:embedded_data".into());
        let mut expected = vec![b'E'; 2];
        expected.extend_from_slice(&[0; 512]);
        expected.extend_from_slice(&[b'B'; 512]);
        assert_eq!(view.read(&cx, 7, 510, 1026).unwrap(), expected);
        assert!(
            !reads
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| *at == BASE as u64 + DATA_A)
        );
        let count = reads.lock().unwrap().len();
        assert_eq!(view.read(&cx, 7, 510, 1026).unwrap(), expected);
        assert_eq!(reads.lock().unwrap().len(), count);
        let bp = BlockPointer::parse(&embedded_pointer(b'E', 20, order, order), order).unwrap();
        assert!(view.checked(&cx, &bp, 18, 0, 512, 30).is_err());
        assert!(view.checked(&cx, &bp, 19, 1, 512, 30).is_err());
        assert!(view.checked(&cx, &bp, 19, 0, 1024, 30).is_err());
        assert!(view.checked(&cx, &bp, 19, 0, 512, 19).is_err());
        view.config.read_features.clear();
        assert!(view.checked(&cx, &bp, 19, 0, 512, 30).is_err());
        assert_eq!(reads.lock().unwrap().len(), count);
    }
}

#[test]
fn invalid_embedded_data_never_becomes_cached_bytes_or_a_successful_read() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for case in 10..=16 {
            let reads: Reads = Arc::default();
            let (leaf, meta) = graph(order, case, Arc::clone(&reads), None);
            let mut view = objects(&leaf, meta);
            // Case 10 is otherwise valid but its mandatory label feature is absent.
            if case != 10 {
                view.config
                    .read_features
                    .push("com.delphix:embedded_data".into());
            }
            assert!(view.read(&cx, 7, 0, 1536).is_err(), "case {case}");
            assert!(!view.cache.iter().any(|(bp, _)| bp.embedded()));
            assert!(
                !reads.lock().unwrap().iter().any(|(at, _)| [
                    BASE as u64 + DATA_A,
                    BASE as u64 + DATA_B
                ]
                .contains(at))
            );
        }
    }
}

fn embedded_pointer_fixed_birth(fill: u8, containing: Endian, payload: Endian) -> Vec<u8> {
    // Fixed LZ4 shape: one literal + 506 repeated bytes + five literals.
    // The native envelope is four length bytes plus twelve LZ4 bytes.
    let mut words = [0_u64; 16];
    words[0] = u64::from_le_bytes([0, 0, 0, 12, 0x1f, fill, 1, 0]);
    words[1] = u64::from_le_bytes([255, 232, 0x50, fill, fill, fill, fill, fill]);
    words[6] = 0x0013_008f_1e00_01ff | (u64::from(payload == Endian::Little) << 63);
    words[10] = 20;
    words
        .into_iter()
        .flat_map(|word| containing.encode(word))
        .collect()
}

#[test]
fn embedded_ranges_use_verified_parents_without_payload_device_reads() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let reads: Reads = Arc::default();
        let (leaf, meta) = graph(order, 17, Arc::clone(&reads), None);
        let mut view = objects(&leaf, meta);
        view.config.read_features = vec![
            "com.delphix:embedded_data".into(),
            "org.illumos:lz4_compress".into(),
        ];
        let mut expected = vec![b'A'; 2];
        expected.extend_from_slice(&[0; 512]);
        expected.extend_from_slice(&[b'B'; 512]);
        assert_eq!(view.read(&cx, 7, 510, 1026).unwrap(), expected);
        assert_eq!(
            *reads.lock().unwrap(),
            [
                (BASE as u64 + TABLE, 16384),
                (BASE as u64 + INDIRECT, 4096),
                (BASE as u64 + DATA_B, 512),
            ]
        );
        let read_count = reads.lock().unwrap().len();
        assert_eq!(view.read(&cx, 7, 510, 1026).unwrap(), expected);
        assert_eq!(view.read(&cx, 7, 0, 512).unwrap(), vec![b'A'; 512]);
        assert_eq!(reads.lock().unwrap().len(), read_count);
    }
}

#[test]
fn embedded_parent_damage_and_later_cancellation_never_return_partial_ranges() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let (leaf, meta) = graph(Endian::Little, 18, Arc::clone(&reads), None);
    let mut view = objects(&leaf, meta);
    view.config.read_features = vec![
        "com.delphix:embedded_data".into(),
        "org.illumos:lz4_compress".into(),
    ];
    assert!(view.read(&cx, 7, 0, 1536).is_err());
    assert!(!view.cache.iter().any(|(bp, _)| bp.embedded()));
    assert_eq!(
        *reads.lock().unwrap(),
        [
            (BASE as u64 + TABLE, 16384),
            (BASE as u64 + INDIRECT, 4096),
        ]
    );

    let reads: Reads = Arc::default();
    let (leaf, meta) = graph(
        Endian::Little,
        17,
        Arc::clone(&reads),
        Some(BASE as u64 + DATA_B),
    );
    let mut view = objects(&leaf, meta);
    view.config.read_features = vec![
        "com.delphix:embedded_data".into(),
        "org.illumos:lz4_compress".into(),
    ];
    assert!(matches!(
        view.read(&cx, 7, 0, 1536),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(
        reads
            .lock()
            .unwrap()
            .iter()
            .filter(|(at, _)| *at == BASE as u64 + DATA_B)
            .count(),
        1
    );
    assert!(
        !reads
            .lock()
            .unwrap()
            .iter()
            .any(|(at, _)| *at == BASE as u64 + DATA_A)
    );
}
