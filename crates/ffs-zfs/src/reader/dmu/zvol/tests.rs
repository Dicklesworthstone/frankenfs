//! Constructed native MOS -> DSL -> volume graphs, not native-pool evidence.
use super::*;
use crate::reader::{Endian, Leaf, RootBlock, VdevConfig};
use ffs_ondisk::zfs::{DATA_OFFSET, LABEL_BYTES, Uberblock, checksum};
use std::sync::{Arc, Mutex};

const BASE: usize = 1024;
const LENGTH: usize = 8 * 1024 * 1024;
const MOS: u64 = DATA_OFFSET + 0x10000;
const DIRECTORY: u64 = DATA_OFFSET + 0x14000;
const NAMES: u64 = DATA_OFFSET + 0x15000;
const HEAD_ROOT: u64 = DATA_OFFSET + 0x18000;
const OLD_ROOT: u64 = DATA_OFFSET + 0x19000;
const HEAD_TABLE: u64 = DATA_OFFSET + 0x20000;
const OLD_TABLE: u64 = DATA_OFFSET + 0x24000;
const HEAD_PROPS: u64 = DATA_OFFSET + 0x28000;
const OLD_PROPS: u64 = DATA_OFFSET + 0x28200;
const HEAD_INDIRECT: u64 = DATA_OFFSET + 0x29000;
const OLD_INDIRECT: u64 = DATA_OFFSET + 0x2a000;
const HEAD_FIRST: u64 = DATA_OFFSET + 0x30000;
const HEAD_LAST: u64 = DATA_OFFSET + 0x31000;
const OLD_FIRST: u64 = DATA_OFFSET + 0x32000;
const OLD_LAST: u64 = DATA_OFFSET + 0x33000;
type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

#[derive(Clone, Copy, Default)]
enum Case {
    #[default]
    Normal,
    NoSize,
    ZeroSize,
    UnalignedSize,
    WrongData,
    WrongProperties,
    Bonus,
    NonPowerBlock,
    Filesystem,
    WrongSnapshotKind,
    WrongLineage,
    FutureChild,
    Huge,
    SmallCapacity,
    Embedded,
    CorruptLast,
    CorruptProperties,
}

fn word16(raw: &mut [u8], at: usize, value: u16, order: Endian) {
    raw[at..at + 2].copy_from_slice(&match order {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    });
}
fn word(raw: &mut [u8], at: usize, value: u64, order: Endian) {
    raw[at..at + 8].copy_from_slice(&order.encode(value));
}
fn pointer(
    data: &[u8],
    at: u64,
    kind: u8,
    level: u8,
    birth: u64,
    order: Endian,
    payload: Endian,
) -> Vec<u8> {
    let sectors = data.len() as u64 / 512;
    let mut words = [0; 16];
    words[0] = sectors;
    words[1] = (at - DATA_OFFSET) / 512;
    words[6] = (sectors - 1)
        | ((sectors - 1) << 16)
        | (2 << 32)
        | (7 << 40)
        | (u64::from(kind) << 48)
        | (u64::from(level) << 56)
        | (u64::from(payload == Endian::Little) << 63);
    words[10] = birth;
    words[12..].copy_from_slice(&checksum(data, 7, payload).unwrap());
    words
        .into_iter()
        .flat_map(|value| order.encode(value))
        .collect()
}
fn node(kind: u8, block_bytes: usize, levels: u8, max: u64, order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = levels;
    raw[3] = 1;
    raw[7] = 1;
    word16(&mut raw, 8, (block_bytes / 512) as u16, order);
    word(&mut raw, 16, max, order);
    raw
}
fn bonus(kind: u8, bytes: &[u8], order: Endian) -> Vec<u8> {
    let mut raw = node(kind, 512, 1, 0, order);
    raw[4] = kind;
    word16(&mut raw, 10, bytes.len() as u16, order);
    raw[192..192 + bytes.len()].copy_from_slice(bytes);
    raw
}
fn micro(rows: &[(&[u8], u64)], order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 512];
    word(&mut raw, 0, (1 << 63) + 3, order);
    for (i, (name, value)) in rows.iter().enumerate() {
        let at = 64 + i * 64;
        word(&mut raw, at, *value, order);
        raw[at + 14..at + 14 + name.len()].copy_from_slice(name);
    }
    raw
}
fn embedded(byte: u8, size: usize, birth: u64, order: Endian) -> Vec<u8> {
    // One literal, distance-one match, five final literals: independent LZ4
    // token construction, not a call to the decoder to manufacture the output.
    let mut stream = vec![0x1f, byte, 1, 0];
    let mut extra = size - 6 - 19;
    while extra >= 255 {
        stream.push(255);
        extra -= 255;
    }
    stream.push(extra as u8);
    stream.push(0x50);
    stream.extend_from_slice(&[byte; 5]);
    let mut packed = (stream.len() as u32).to_be_bytes().to_vec();
    packed.extend(stream);
    let packed_len = packed.len();
    packed.resize(112, 0);
    let mut words = [0; 16];
    let mut at = 0;
    for (index, value) in words.iter_mut().enumerate() {
        if index != 6 && index != 10 {
            *value = u64::from_le_bytes(packed[at..at + 8].try_into().unwrap());
            at += 8;
        }
    }
    words[6] = (size as u64 - 1)
        | ((packed_len as u64 - 1) << 25)
        | (15 << 32)
        | (1 << 39)
        | (23 << 48)
        | (u64::from(order == Endian::Little) << 63);
    words[10] = birth;
    words
        .into_iter()
        .flat_map(|value| order.encode(value))
        .collect()
}

struct Fixture {
    image: Vec<u8>,
    root: RootBlock,
}
impl Fixture {
    fn new(order: Endian, case: Case) -> Self {
        let other = if order == Endian::Little {
            Endian::Big
        } else {
            Endian::Little
        };
        let mut image = vec![0; BASE + LENGTH + 512];
        image[..BASE].fill(0xa5);
        image[BASE + LENGTH..].fill(0x5a);
        let mut store = |at: u64, bytes: &[u8]| {
            let at = BASE + at as usize;
            image[at..at + bytes.len()].copy_from_slice(bytes);
        };
        let mut volume_roots = Vec::new();
        for (old, table_at, root_at, props_at, ind_at, first_at, last_at) in [
            (
                false,
                HEAD_TABLE,
                HEAD_ROOT,
                HEAD_PROPS,
                HEAD_INDIRECT,
                HEAD_FIRST,
                HEAD_LAST,
            ),
            (
                true,
                OLD_TABLE,
                OLD_ROOT,
                OLD_PROPS,
                OLD_INDIRECT,
                OLD_FIRST,
                OLD_LAST,
            ),
        ] {
            let block = if matches!(case, Case::NonPowerBlock) {
                3072
            } else {
                4096
            };
            let data_kind = if matches!(case, Case::WrongData) {
                19
            } else {
                23
            };
            let props_kind = if matches!(case, Case::WrongProperties) {
                196
            } else {
                24
            };
            let mut size = (block * if old { 4 } else { 8 }) as u64;
            match case {
                Case::ZeroSize => size = 0,
                Case::UnalignedSize => size += 1,
                Case::Huge => size = 1 << 50,
                Case::SmallCapacity => size = block as u64,
                _ => {}
            }
            let props = micro(
                &[(
                    if matches!(case, Case::NoSize) {
                        b"lost"
                    } else {
                        b"size"
                    },
                    size,
                )],
                other,
            );
            let first = vec![if old { b'A' } else { b'E' }; block];
            let last = vec![if old { b'B' } else { b'F' }; block];
            let leaf_birth = if old { 20 } else { 60 };
            let mut indirect = vec![0; 4096];
            for (slot, at, bytes) in [(0, first_at, &first), (2, last_at, &last)] {
                let birth = if old && matches!(case, Case::FutureChild) {
                    26
                } else {
                    leaf_birth
                };
                let bp = if matches!(case, Case::Embedded) {
                    embedded(bytes[0], block, birth, other)
                } else {
                    pointer(bytes, at, data_kind, 0, birth, other, order)
                };
                indirect[slot * 128..(slot + 1) * 128].copy_from_slice(&bp);
            }
            store(first_at, &first);
            store(last_at, &last);
            store(ind_at, &indirect);
            store(props_at, &props);
            let mut table = vec![0; 16384];
            let mut data = node(
                data_kind,
                block,
                2,
                if matches!(case, Case::NonPowerBlock) {
                    0
                } else {
                    2
                },
                order,
            );
            data[64..192].copy_from_slice(&pointer(
                &indirect,
                ind_at,
                data_kind,
                1,
                if old { 25 } else { 70 },
                order,
                other,
            ));
            if matches!(case, Case::Bonus) {
                word16(&mut data, 10, 8, order);
                data[192] = 1;
            }
            word(&mut data, 24, 2 * block as u64, order);
            table[512..1024].copy_from_slice(&data);
            let mut prop_node = node(props_kind, 512, 1, 0, order);
            prop_node[64..192].copy_from_slice(&pointer(
                &props,
                props_at,
                props_kind,
                0,
                if old { 22 } else { 65 },
                order,
                other,
            ));
            table[1024..1536].copy_from_slice(&prop_node);
            store(table_at, &table);
            let mut root = vec![0; 1024];
            let mut meta = node(10, 16384, 1, 0, other);
            meta[64..192].copy_from_slice(&pointer(
                &table,
                table_at,
                10,
                0,
                if old { 29 } else { 75 },
                other,
                order,
            ));
            root[..512].copy_from_slice(&meta);
            let kind = if matches!(case, Case::Filesystem)
                || old && matches!(case, Case::WrongSnapshotKind)
            {
                2
            } else {
                3
            };
            word(&mut root, 704, kind, other);
            store(root_at, &root);
            volume_roots.push(pointer(
                &root,
                root_at,
                11,
                0,
                if old { 30 } else { 80 },
                order,
                other,
            ));
        }
        let mut mos = vec![0; 16384];
        let directory = micro(
            &[
                (b"root_dataset", 2),
                (b"features_for_read", 29),
                (b"features_for_write", 30),
                (b"feature_descriptions", 31),
            ],
            other,
        );
        let names = micro(&[(b"before", 5)], other);
        let features = micro(
            &[
                (b"org.illumos:lz4_compress", 1),
                (b"com.delphix:embedded_data", 1),
            ],
            order,
        );
        for (id, at, bytes, kind, payload) in [
            (1, DIRECTORY, directory, 1, other),
            (4, NAMES, names, 14, other),
            (29, DATA_OFFSET + 0x14400, features, 196, order),
            (30, DATA_OFFSET + 0x14600, micro(&[], order), 196, order),
            (31, DATA_OFFSET + 0x14800, micro(&[], order), 196, order),
        ] {
            let mut raw = node(kind, 512, 1, 0, order);
            raw[64..192].copy_from_slice(&pointer(&bytes, at, kind, 0, 85, order, payload));
            mos[id * 512..(id + 1) * 512].copy_from_slice(&raw);
            store(at, &bytes);
        }
        let mut directory = vec![0; 256];
        word(&mut directory, 8, 3, order);
        mos[1024..1536].copy_from_slice(&bonus(12, &directory, order));
        for (id, index, creation, previous, previous_txg, next, names, children) in [
            (3, 0, 10, 5, 40, 0, 4, 0),
            (
                5,
                1,
                40,
                0,
                0,
                if matches!(case, Case::WrongLineage) {
                    5
                } else {
                    3
                },
                0,
                1,
            ),
        ] {
            let mut raw = vec![0; 320];
            for (at, value) in [
                (0, 2),
                (8, previous),
                (16, previous_txg),
                (24, next),
                (32, names),
                (40, children),
                (56, creation),
                (72, 16384),
                (112, 1000 + id),
                (120, 4),
            ] {
                word(&mut raw, at, value, order);
            }
            raw[128..256].copy_from_slice(&volume_roots[index]);
            mos[id as usize * 512..(id as usize + 1) * 512]
                .copy_from_slice(&bonus(16, &raw, order));
        }
        store(MOS, &mos);
        let mut root = vec![0; 1024];
        let mut meta = node(10, 16384, 1, 0, other);
        meta[64..192].copy_from_slice(&pointer(&mos, MOS, 10, 0, 90, other, order));
        root[..512].copy_from_slice(&meta);
        word(&mut root, 704, 1, other);
        let root_pointer = BlockPointer::parse(
            &pointer(&root, DATA_OFFSET, 11, 0, 100, order, other),
            order,
        )
        .unwrap();
        if matches!(case, Case::CorruptLast) {
            image[BASE + OLD_LAST as usize] ^= 1;
        }
        if matches!(case, Case::CorruptProperties) {
            image[BASE + OLD_PROPS as usize] ^= 1;
        }
        Self {
            image,
            root: RootBlock {
                uberblock: Uberblock {
                    order,
                    version: 5000,
                    txg: 110,
                    guid_sum: 1122,
                    timestamp: 1,
                    root: root_pointer,
                },
                data: root,
                physical_offset: DATA_OFFSET,
                copy_index: 0,
                member_guid: 999,
                raidz: None,
                config: VdevConfig {
                    pool_guid: 123,
                    top_guid: 999,
                    version: 5000,
                    txg: 100,
                    ashift: 9,
                    id: 0,
                    allocated_bytes: LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES,
                    read_features: vec![
                        "org.illumos:lz4_compress".into(),
                        "com.delphix:embedded_data".into(),
                    ],
                    raidz_members: None,
                },
            },
        }
    }

    fn open(self, fault: Option<u64>) -> (Objects, Reads) {
        let reads = Arc::default();
        let leaf = Leaf::from_device(
            &Cx::for_testing(),
            Box::new(Memory {
                image: self.image,
                reads: Arc::clone(&reads),
                fault,
            }),
            BASE as u64,
            LENGTH as u64,
        )
        .unwrap();
        (
            Objects::from_root(&Cx::for_testing(), leaf.into(), self.root).unwrap(),
            reads,
        )
    }
}
struct Memory {
    image: Vec<u8>,
    reads: Reads,
    fault: Option<u64>,
}
impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 {
        self.image.len() as u64
    }
    fn read_exact_at(&self, _: &Cx, at: ByteOffset, out: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push((at.0, out.len()));
        if self.fault == Some(at.0) {
            return Err(FfsError::Cancelled);
        }
        let start = at.0 as usize;
        out.copy_from_slice(
            self.image
                .get(start..start + out.len())
                .ok_or_else(|| corrupt("test read out of bounds"))?,
        );
        Ok(())
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("zvol wrote backing image")
    }
    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("zvol flushed backing image")
    }
}
fn expected(old: bool, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    bytes[..4096].fill(if old { b'A' } else { b'E' });
    bytes[8192..12288].fill(if old { b'B' } else { b'F' });
    bytes
}

#[test]
fn heads_and_snapshots_use_native_volume_objects_and_independent_capacities() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let (mut pool, _) = Fixture::new(order, Case::Normal).open(None);
        let mut head = pool.zvol(&cx, &[], None).unwrap();
        let mut old = pool.zvol(&cx, &[], Some(b"before")).unwrap();
        assert_eq!((head.len_bytes(), old.len_bytes()), (32768, 16384));
        assert_eq!(
            (head.info().dataset_guid, old.info().dataset_guid),
            (1003, 1005)
        );
        assert_eq!((head.info().view_txg, old.info().view_txg), (110, 40));
        assert_eq!((head.info().root_birth, old.info().root_birth), (80, 30));
        assert_eq!(head.info().block_bytes, 4096);
        assert!(!head.info().snapshot && old.info().snapshot);
        for _ in 0..2 {
            assert_eq!(head.read(&cx, 0, 32768).unwrap(), expected(false, 32768));
            assert_eq!(
                old.read(&cx, 4071, 8230).unwrap(),
                expected(true, 16384)[4071..12301]
            );
        }
        drop(pool);
        assert_eq!(old.read(&cx, 0, 16384).unwrap(), expected(true, 16384));
        assert_eq!(head.read(&cx, 0, 16).unwrap(), [b'E'; 16]);
    }
}

#[test]
fn sparse_capacity_can_exceed_allocated_tree_geometry_without_invented_io() {
    let cx = Cx::for_testing();
    let (mut pool, reads) = Fixture::new(Endian::Little, Case::Huge).open(None);
    let mut old = pool.zvol(&cx, &[], Some(b"before")).unwrap();
    reads.lock().unwrap().clear();
    assert_eq!(old.read(&cx, (1 << 50) - 137, 137).unwrap(), [0; 137]);
    assert_eq!(
        old.seek_data_hole(&cx, (1 << 50) - 137, false).unwrap(),
        (1 << 50) - 137
    );
    assert!(old.seek_data_hole(&cx, (1 << 50) - 137, true).is_err());
    assert!(reads.lock().unwrap().is_empty());
}

#[test]
fn exact_device_ranges_and_overflow_fail_before_io_and_preserve_buffers() {
    let cx = Cx::for_testing();
    let (mut pool, reads) = Fixture::new(Endian::Little, Case::Normal).open(None);
    let old = pool.zvol(&cx, &[], Some(b"before")).unwrap();
    reads.lock().unwrap().clear();
    for start in [16380, 16384, u64::MAX - 3, u64::MAX] {
        let mut bytes = [0xa5; 8];
        assert!(
            old.read_exact_at(&cx, ByteOffset(start), &mut bytes)
                .is_err()
        );
        assert_eq!(bytes, [0xa5; 8]);
    }
    assert!(old.read_exact_at(&cx, ByteOffset(16384), &mut []).is_ok());
    assert!(old.read_exact_at(&cx, ByteOffset(16385), &mut []).is_err());
    assert!(check_range(u64::MAX, 0, MAX_READ_BYTES + 1).is_err());
    assert!(reads.lock().unwrap().is_empty());
}

#[test]
fn a_bad_later_block_never_publishes_earlier_data_or_a_successful_vector_prefix() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let (mut pool, _) = Fixture::new(order, Case::CorruptLast).open(None);
        let old = pool.zvol(&cx, &[], Some(b"before")).unwrap();
        let mut out = vec![0xa5; 12288];
        assert!(old.read_exact_at(&cx, ByteOffset(0), &mut out).is_err());
        assert_eq!(out, vec![0xa5; 12288]);
        let mut first = [0xc3; 4096];
        let mut rest = [0xd7; 8192];
        let mut parts = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut rest)];
        assert!(
            old.read_vectored_exact_at(&cx, ByteOffset(0), &mut parts)
                .is_err()
        );
        assert_eq!(first, [0xc3; 4096]);
        assert_eq!(rest, [0xd7; 8192]);
        assert!(old.preserves_read_exact_at_destination_on_error());
        assert!(old.preserves_read_vectored_destinations_on_error());
    }
}

#[test]
fn cancellation_is_terminal_and_does_not_return_head_bytes() {
    let cx = Cx::for_testing();
    let (mut pool, reads) =
        Fixture::new(Endian::Big, Case::Normal).open(Some(BASE as u64 + OLD_LAST));
    let old = pool.zvol(&cx, &[], Some(b"before")).unwrap();
    let mut out = [0xa5; 12288];
    assert!(matches!(
        old.read_exact_at(&cx, ByteOffset(0), &mut out),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(out, [0xa5; 12288]);
    assert_eq!(
        reads.lock().unwrap().last(),
        Some(&(BASE as u64 + OLD_LAST, 4096))
    );
    assert!(
        !reads
            .lock()
            .unwrap()
            .iter()
            .any(|(at, _)| *at == BASE as u64 + HEAD_FIRST)
    );
}

#[test]
fn native_metadata_geometry_and_snapshot_lineage_fail_closed() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for case in [
            Case::NoSize,
            Case::ZeroSize,
            Case::UnalignedSize,
            Case::WrongData,
            Case::WrongProperties,
            Case::Bonus,
            Case::NonPowerBlock,
            Case::Filesystem,
            Case::WrongSnapshotKind,
            Case::WrongLineage,
            Case::CorruptProperties,
        ] {
            let (mut pool, _) = Fixture::new(order, case).open(None);
            assert!(pool.zvol(&cx, &[], Some(b"before")).is_err());
        }
        let (mut pool, _) = Fixture::new(order, Case::Normal).open(None);
        for name in [b"BEFORE".as_slice(), b"absent", b"", b"..", b"a/b", b"x\0y"] {
            assert!(pool.zvol(&cx, &[], Some(name)).is_err());
        }
        assert!(pool.zvol(&cx, &[b"absent".to_vec()], None).is_err());
    }
}

#[test]
fn snapshot_birth_checks_apply_to_volume_data_and_allocation_queries() {
    let cx = Cx::for_testing();
    let (mut pool, _) = Fixture::new(Endian::Little, Case::FutureChild).open(None);
    let mut old = pool.zvol(&cx, &[], Some(b"before")).unwrap();
    assert!(old.read(&cx, 0, 1).is_err());
    assert!(old.seek_data_hole(&cx, 0, true).is_err());
    assert_eq!(
        pool.zvol(&cx, &[], None).unwrap().read(&cx, 0, 1).unwrap(),
        b"E"
    );
}

#[test]
fn compressed_embedded_volume_blocks_use_parent_integrity_without_payload_io() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let (mut pool, reads) = Fixture::new(order, Case::Embedded).open(None);
        let mut old = pool.zvol(&cx, &[], Some(b"before")).unwrap();
        assert_eq!(old.read(&cx, 0, 16384).unwrap(), expected(true, 16384));
        assert_eq!(old.seek_data_hole(&cx, 1, false).unwrap(), 4096);
        assert_eq!(old.seek_data_hole(&cx, 4096, true).unwrap(), 8192);
        assert!(
            !reads
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| [OLD_FIRST, OLD_LAST].iter().any(|p| *at == BASE as u64 + p))
        );
    }
}

#[test]
fn bytes_allocated_past_a_shrunken_capacity_are_not_exposed() {
    let cx = Cx::for_testing();
    let (mut pool, reads) = Fixture::new(Endian::Little, Case::SmallCapacity).open(None);
    let mut old = pool.zvol(&cx, &[], Some(b"before")).unwrap();
    assert_eq!(old.len_bytes(), 4096);
    assert_eq!(old.read(&cx, 0, 4096).unwrap(), [b'A'; 4096]);
    assert!(old.read(&cx, 4096, 1).is_err());
    assert!(
        !reads
            .lock()
            .unwrap()
            .iter()
            .any(|(at, _)| *at == BASE as u64 + OLD_LAST)
    );
}

#[test]
fn readonly_device_sync_and_rejected_writes_never_touch_the_pool() {
    let cx = Cx::for_testing();
    let (mut pool, reads) = Fixture::new(Endian::Little, Case::Normal).open(None);
    let old = pool.zvol(&cx, &[], Some(b"before")).unwrap();
    reads.lock().unwrap().clear();
    assert!(matches!(
        old.write_all_at(&cx, ByteOffset(0), b"x"),
        Err(FfsError::ReadOnly)
    ));
    old.sync(&cx).unwrap();
    assert!(reads.lock().unwrap().is_empty());
    let mut first = [0; 50];
    let mut empty = [];
    let mut rest = [0; 70];
    let mut parts = [
        IoSliceMut::new(&mut first),
        IoSliceMut::new(&mut empty),
        IoSliceMut::new(&mut rest),
    ];
    old.read_vectored_exact_at(&cx, ByteOffset(4050), &mut parts)
        .unwrap();
    assert_eq!(first.as_slice(), &expected(true, 16384)[4050..4100]);
    assert_eq!(rest, [0; 70]);
}

mod redundancy;
