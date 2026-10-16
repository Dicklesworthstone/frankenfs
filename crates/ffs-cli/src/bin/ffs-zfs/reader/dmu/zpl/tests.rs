use super::*;
use crate::reader::dmu::features::tests::{GRAPH_DIRECTORY, install_graph_catalogs};
use crate::reader::dmu::tests::embedded_pointer;
use crate::reader::{ByteOffset, DATA_OFFSET, Endian, LABEL_BYTES, Leaf, VdevConfig};
use ffs_block::ByteDevice;
use ffs_ondisk::zfs::checksum;
use ffs_ondisk::zfs_dmu::Dnode;
use std::sync::{Arc, Mutex};

const BASE: usize = 1024;
const LENGTH: usize = 8 * 1024 * 1024;
const MOS: u64 = DATA_OFFSET + 0x10000;
const POOL_MAP: u64 = DATA_OFFSET + 0x14000;
const OS: u64 = DATA_OFFSET + 0x18000;
const TABLE: u64 = DATA_OFFSET + 0x20000;
const MASTER: u64 = DATA_OFFSET + 0x25000;
const ROOT_MAP: u64 = DATA_OFFSET + 0x26000;
const SUB_MAP: u64 = DATA_OFFSET + 0x27000;
const FIRST: u64 = DATA_OFFSET + 0x28000;
const LAST: u64 = DATA_OFFSET + 0x2a000;
const SA_MASTER: u64 = DATA_OFFSET + 0x2c000;
const SA_REGISTRY: u64 = DATA_OFFSET + 0x2d000;
const INDIRECT: u64 = DATA_OFFSET + 0x2e000;
const SA_LAYOUTS: u64 = DATA_OFFSET + 0x30000;
const SPILL: u64 = DATA_OFFSET + 0x32000;
type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

fn u16put(raw: &mut [u8], at: usize, value: u16, order: Endian) {
    raw[at..at + 2].copy_from_slice(&match order {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    });
}
fn bp(
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
fn node(
    kind: u8,
    block: usize,
    levels: u8,
    max: u64,
    bonus: &[u8],
    bonus_type: u8,
    order: Endian,
) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = levels;
    raw[3] = 1;
    raw[4] = bonus_type;
    raw[7] = 1;
    u16put(&mut raw, 8, (block / 512) as u16, order);
    u16put(&mut raw, 10, bonus.len() as u16, order);
    raw[16..24].copy_from_slice(&order.encode(max));
    raw[192..192 + bonus.len()].copy_from_slice(bonus);
    raw
}
fn legacy(mode: u64, size: u64, parent: u64, order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 264];
    for (at, value) in [
        (0, 1_700_000_000),
        (8, 123),
        (64, 10),
        (72, mode),
        (80, size),
        (88, parent),
        (96, 2),
        (128, 1000),
        (136, 100),
    ] {
        raw[at..at + 8].copy_from_slice(&order.encode(value));
    }
    raw
}
fn micro(entries: &[(&[u8], u64)], order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[..8].copy_from_slice(&order.encode((1 << 63) + 3));
    for (i, (name, value)) in entries.iter().enumerate() {
        let at = 64 + i * 64;
        raw[at..at + 8].copy_from_slice(&order.encode(*value));
        raw[at + 14..at + 14 + name.len()].copy_from_slice(name);
    }
    raw
}
fn sa_fields(order: Endian) -> Vec<(u16, Vec<u8>)> {
    let raw = legacy(0o100_640, 1027, 2, order);
    [
        (6, 80, 8),
        (3, 48, 16),
        (0, 0, 16),
        (12, 128, 8),
        (13, 136, 8),
        (5, 72, 8),
        (2, 32, 16),
        (4, 64, 8),
        (8, 96, 8),
        (1, 16, 16),
        (11, 120, 8),
        (7, 88, 8),
    ]
    .into_iter()
    .map(|(id, at, len)| (id, raw[at..at + len].to_vec()))
    .collect()
}
fn sa_bytes(layout: u16, fields: &[(u16, Vec<u8>)], order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 8];
    raw[..4].copy_from_slice(&match order {
        Endian::Little => [0x5a, 0x50, 0x2f, 0],
        Endian::Big => [0, 0x2f, 0x50, 0x5a],
    });
    u16put(&mut raw, 4, 1024 | layout, order);
    for (_, bytes) in fields {
        raw.extend_from_slice(bytes);
    }
    raw
}

// A native fat-ZAP fixture is needed because layout IDs contain uint16 arrays,
// not micro-ZAP uint64 scalars. Hash constants were generated independently.
fn layouts(arrays: &[Vec<u16>], order: Endian) -> (Vec<u8>, Vec<u8>) {
    let mut header = vec![0; 512];
    for (at, value) in [
        (0, (1_u64 << 63) + 1),
        (8, 0x0002_f52a_b2ab),
        (56, 2),
        (64, 1),
        (72, arrays.len() as u64),
        (80, 99),
        (256, 1),
    ] {
        header[at..at + 8].copy_from_slice(&order.encode(value));
    }
    let mut leaf = vec![0; 512];
    leaf[..8].copy_from_slice(&order.encode(1 << 63));
    leaf[24..28].copy_from_slice(&match order {
        Endian::Little => 0x02ab_1eaf_u32.to_le_bytes(),
        Endian::Big => 0x02ab_1eaf_u32.to_be_bytes(),
    });
    leaf[48..80].fill(0xff);
    let mut next = 0_u16;
    for (i, array) in arrays.iter().enumerate() {
        let hash = [0xaa03_c640_0000_0000_u64, 0x192d_8af0_0000_0000][i];
        let entry = next;
        let name_chunk = next + 1;
        let value_chunk = next + 2;
        let bytes: Vec<_> = array.iter().flat_map(|value| value.to_be_bytes()).collect();
        let chunks = bytes.len().div_ceil(21) as u16;
        let at = 80 + usize::from(entry) * 24;
        leaf[at] = 252;
        leaf[at + 1] = 2;
        for (off, value) in [
            (2, 0xffff),
            (4, name_chunk),
            (6, 2),
            (8, value_chunk),
            (10, array.len() as u16),
        ] {
            u16put(&mut leaf, at + off, value, order);
        }
        leaf[at + 16..at + 24].copy_from_slice(&order.encode(hash));
        u16put(&mut leaf, 48 + (hash >> 60) as usize * 2, entry, order);
        let at = 80 + usize::from(name_chunk) * 24;
        leaf[at] = 251;
        leaf[at + 1] = b'2' + i as u8;
        u16put(&mut leaf, at + 22, 0xffff, order);
        for (j, part) in bytes.chunks(21).enumerate() {
            let at = 80 + (usize::from(value_chunk) + j) * 24;
            leaf[at] = 251;
            leaf[at + 1..at + 1 + part.len()].copy_from_slice(part);
            u16put(
                &mut leaf,
                at + 22,
                if j + 1 == usize::from(chunks) {
                    0xffff
                } else {
                    value_chunk + j as u16 + 1
                },
                order,
            );
        }
        next += 2 + chunks;
    }
    u16put(&mut leaf, 28, 18 - next, order);
    u16put(&mut leaf, 30, arrays.len() as u16, order);
    u16put(&mut leaf, 34, if next == 18 { 0xffff } else { next }, order);
    for i in next..18 {
        let at = 80 + usize::from(i) * 24;
        leaf[at] = 253;
        u16put(
            &mut leaf,
            at + 22,
            if i == 17 { 0xffff } else { i + 1 },
            order,
        );
    }
    (header, leaf)
}

/// Constructed graph, not native-pool evidence. Includes MOS -> DSL -> objset ->
/// master node -> namespace -> file and, for SA, real registry/layout ZAP reads.
fn graph(order: Endian, sa: u8, case: u8, reads: Reads, failure: Option<u64>) -> (Leaf, Dnode) {
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
    let mut table = vec![0; 16_384];
    let mut master_items: Vec<(&[u8], u64)> =
        vec![(b"ROOT", 2), (b"VERSION", if sa == 0 { 4 } else { 5 })];
    if sa != 0 {
        master_items.push((b"SA_ATTRS", 8));
    }
    if case == 7 {
        master_items.push((b"normalization", 1));
    }
    let master = micro(&master_items, other);
    store(MASTER, &master);
    let mut master_node = node(21, 512, 1, 0, &[], 0, order);
    master_node[64..192].copy_from_slice(&bp(&master, MASTER, 21, 0, 20, order, other));
    table[512..1024].copy_from_slice(&master_node);
    let root = micro(
        &[
            (b"file.bin", ((if case == 1 { 4 } else { 8 }) << 60) | 3),
            (b"alias.bin", (8 << 60) | 3),
            (b"sub", (4 << 60) | if case == 3 { 2 } else { 4 }),
            (b"link", (10 << 60) | 5),
            (b"empty", (8 << 60) | 6),
            (b"sparse", (8 << 60) | 7),
        ],
        other,
    );
    let sub = micro(&[(b"nested", (8 << 60) | 3)], order);
    store(ROOT_MAP, &root);
    store(SUB_MAP, &sub);
    for (number, data, at, payload, parent) in [
        (2, &root, ROOT_MAP, other, 2),
        (4, &sub, SUB_MAP, order, if case == 2 { 9 } else { 2 }),
    ] {
        let mut dn = node(
            20,
            512,
            1,
            0,
            &legacy(0o040_755, 2, parent, order),
            17,
            order,
        );
        dn[64..192].copy_from_slice(&bp(data, at, 20, 0, 20, order, payload));
        table[number * 512..(number + 1) * 512].copy_from_slice(&dn);
    }
    let block_bytes = if case == 32 { 1024 } else { 512 };
    let file_size = if case == 32 { 2051 } else { 1027 };
    let a = vec![b'A'; block_bytes];
    let b = vec![b'B'; block_bytes];
    store(FIRST, &a);
    store(LAST, &b);
    let mut indirect = vec![0; 4096];
    indirect[..128].copy_from_slice(&bp(&a, FIRST, 19, 0, 20, other, order));
    indirect[256..384].copy_from_slice(&bp(&b, LAST, 19, 0, 20, other, order));
    if (9..=11).contains(&case) {
        indirect[..128].copy_from_slice(&embedded_pointer(b'A', 20, other, order));
        indirect[256..384].copy_from_slice(&embedded_pointer(b'B', 20, other, order));
        if case == 10 {
            indirect[256..264].copy_from_slice(&other.encode(u64::MAX));
        }
    }
    store(INDIRECT, &indirect);
    let mut fields = sa_fields(other);
    if case == 32 {
        fields.iter_mut().find(|(id, _)| *id == 6).unwrap().1 = other.encode(file_size).to_vec();
    }
    let bonus = match sa {
        0 => legacy(0o100_640, file_size, 2, order),
        1 => sa_bytes(2, &fields, other),
        _ => sa_bytes(2, &fields[..5], other),
    };
    let mut file = node(
        19,
        block_bytes,
        2,
        2,
        &bonus,
        if sa == 0 { 17 } else { 44 },
        order,
    );
    file[64..192].copy_from_slice(&bp(&indirect, INDIRECT, 19, 1, 30, order, other));
    if case == 11 {
        indirect[0] ^= 1;
        store(INDIRECT, &indirect);
    }
    file[24..32].copy_from_slice(&order.encode(5120));
    if case == 4 && sa == 0 {
        file[192 + 64..192 + 72].copy_from_slice(&order.encode(99));
    }
    if sa == 2 {
        let other_fields = sa_fields(order);
        let mut spill = sa_bytes(3, &other_fields[5..], order);
        spill.resize(512, 0);
        file[7] |= 4;
        file[384..512].copy_from_slice(&bp(&spill, SPILL, 44, 0, 20, order, order));
        if case == 5 {
            spill[20] ^= 1;
        }
        store(SPILL, &spill);
    }
    table[3 * 512..4 * 512].copy_from_slice(&file);
    let mut link = legacy(0o120_777, 8, 2, order);
    link.extend_from_slice(b"file.bin");
    table[5 * 512..6 * 512].copy_from_slice(&node(19, 512, 1, 0, &link, 17, order));
    for (number, size) in [(6, 0), (7, (1_u64 << 40) + 5)] {
        table[number * 512..(number + 1) * 512].copy_from_slice(&node(
            19,
            512,
            1,
            0,
            &legacy(0o100_600, size, 2, order),
            17,
            order,
        ));
    }
    if sa != 0 {
        let master = micro(&[(b"REGISTRY", 9), (b"LAYOUTS", 10)], order);
        let registry = micro(
            &[(
                b"ZPL_SYMLINK",
                u64::from(if case == 6 { 6_u16 } else { 47 }) | (3 << 16),
            )],
            order,
        );
        for (number, kind, data, at) in [(8, 45, master, SA_MASTER), (9, 46, registry, SA_REGISTRY)]
        {
            store(at, &data);
            let mut dn = node(kind, 512, 1, 0, &[], 0, order);
            dn[64..192].copy_from_slice(&bp(&data, at, kind, 0, 20, order, order));
            table[number * 512..(number + 1) * 512].copy_from_slice(&dn);
        }
        let ids: Vec<_> = fields.iter().map(|(id, _)| *id).collect();
        let arrays = if sa == 1 {
            vec![ids]
        } else {
            vec![ids[..5].to_vec(), ids[5..].to_vec()]
        };
        let (header, leaf) = layouts(&arrays, other);
        store(SA_LAYOUTS, &header);
        store(SA_LAYOUTS + 512, &leaf);
        let mut dn = node(47, 512, 1, 1, &[], 0, order);
        dn[3] = 2;
        dn[64..192].copy_from_slice(&bp(&header, SA_LAYOUTS, 47, 0, 20, order, other));
        dn[192..320].copy_from_slice(&bp(&leaf, SA_LAYOUTS + 512, 47, 0, 20, order, other));
        table[10 * 512..11 * 512].copy_from_slice(&dn);
    }
    if (12..32).contains(&case) {
        xattrs::augment(&mut table, &mut store, order, sa, case);
    }
    store(TABLE, &table);
    let mut os = vec![0; 1024];
    let mut meta = node(10, 16_384, 1, 0, &[], 0, other);
    meta[64..192].copy_from_slice(&bp(&table, TABLE, 10, 0, 40, other, order));
    os[..512].copy_from_slice(&meta);
    os[704..712].copy_from_slice(&other.encode(2));
    store(OS, &os);
    let mut mos_table = vec![0; 16_384];
    let pool = micro(GRAPH_DIRECTORY, order);
    store(POOL_MAP, &pool);
    let mut dn = node(1, 512, 1, 0, &[], 0, order);
    dn[64..192].copy_from_slice(&bp(&pool, POOL_MAP, 1, 0, 20, order, order));
    mos_table[512..1024].copy_from_slice(&dn);
    let mut dir = vec![0; 256];
    dir[8..16].copy_from_slice(&order.encode(3));
    mos_table[1024..1536].copy_from_slice(&node(12, 512, 1, 0, &dir, 12, order));
    let mut ds = vec![0; 320];
    for (at, value) in [(0, 2), (56, 5), (112, 987), (120, 4)] {
        ds[at..at + 8].copy_from_slice(&order.encode(value));
    }
    ds[128..256].copy_from_slice(&bp(
        &os,
        OS,
        11,
        0,
        if case == 8 { 55 } else { 45 },
        order,
        other,
    ));
    mos_table[1536..2048].copy_from_slice(&node(16, 512, 1, 0, &ds, 16, order));
    for (at, bytes) in install_graph_catalogs(&mut mos_table, order) {
        store(at, &bytes);
    }
    store(MOS, &mos_table);
    let mut meta = node(10, 16_384, 1, 0, &[], 0, order);
    meta[64..192].copy_from_slice(&bp(&mos_table, MOS, 10, 0, 50, order, order));
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
    (leaf, Dnode::parse(&meta, order).unwrap())
}
fn mos(leaf: &Leaf, meta: Dnode) -> Objects {
    Objects {
        pool: leaf.clone().into(),
        config: VdevConfig {
            pool_guid: 123,
            top_guid: 999,
            version: 5000,
            txg: 60,
            ashift: 9,
            id: 0,
            allocated_bytes: LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES,
            read_features: Vec::new(),
            raidz_members: None,
        },
        txg: 61,
        root_birth: 60,
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
    fn read_exact_at(&self, _: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push((offset.0, bytes.len()));
        if self.failure == Some(offset.0) {
            return Err(FfsError::Cancelled);
        }
        let at = offset.0 as usize;
        bytes.copy_from_slice(
            self.image
                .get(at..at + bytes.len())
                .ok_or_else(|| corrupt("test read out of bounds"))?,
        );
        Ok(())
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("ZPL reader wrote the image")
    }
    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("ZPL reader flushed the image")
    }
}

#[test]
fn selected_dataset_reads_legacy_sa_and_spill_files_without_exposing_slack() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for sa in 0..=2 {
            let (leaf, meta) = graph(order, sa, 0, Arc::default(), None);
            let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
            assert_eq!((view.root, view.dataset_guid), (2, 987));
            let id = view.resolve(&cx, b"/file.bin").unwrap();
            assert_eq!(id, 3);
            assert_eq!(view.resolve(&cx, b"/alias.bin").unwrap(), id);
            assert_eq!(view.resolve(&cx, b"/sub/nested").unwrap(), id);
            let mut expected = vec![b'A'; 512];
            expected.extend_from_slice(&[0; 512]);
            expected.extend_from_slice(b"BBB");
            assert_eq!(view.read(&cx, id, 0, 4096).unwrap(), expected);
            assert_eq!(view.read(&cx, id, 510, 600).unwrap(), expected[510..]);
            assert_eq!(view.read(&cx, id, 1027, 5).unwrap(), [] as [u8; 0]);
            assert_eq!(view.read(&cx, id, u64::MAX, 5).unwrap(), [] as [u8; 0]);
            let (metadata, allocated) = view.stat(&cx, id).unwrap();
            assert_eq!(
                (metadata.size, metadata.links, metadata.uid, allocated),
                (1027, 2, 1000, 5120)
            );
            assert_eq!(view.list(&cx, view.root).unwrap().len(), 6);
        }
    }
}
#[test]
fn embedded_file_blocks_preserve_unaligned_eof_hardlinks_and_sa_metadata() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for sa in 0..=2 {
            let reads: Reads = Arc::default();
            let (leaf, meta) = graph(order, sa, 9, Arc::clone(&reads), None);
            let mut pool = mos(&leaf, meta);
            pool.config
                .read_features
                .push("com.delphix:embedded_data".into());
            let mut view = pool.zpl(&cx, &[]).unwrap();
            assert_eq!(view.resolve(&cx, b"/alias.bin").unwrap(), 3);
            let mut expected = vec![b'A'; 512];
            expected.extend_from_slice(&[0; 512]);
            expected.extend_from_slice(b"BBB");
            assert_eq!(view.read(&cx, 3, 0, 4096).unwrap(), expected);
            assert_eq!(view.read(&cx, 3, 510, 600).unwrap(), expected[510..]);
            assert_eq!(view.read(&cx, 3, 1027, 8).unwrap(), [] as [u8; 0]);
            assert_eq!(view.stat(&cx, 3).unwrap().0.size, 1027);
            assert!(
                !reads.lock().unwrap().iter().any(|(at, _)| [
                    BASE as u64 + FIRST,
                    BASE as u64 + LAST
                ]
                .contains(at))
            );
        }
    }
}

#[test]
fn embedded_file_corruption_fails_the_request_without_returning_a_prefix() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for case in [10, 11] {
            let reads: Reads = Arc::default();
            let (leaf, meta) = graph(order, 2, case, Arc::clone(&reads), None);
            let mut pool = mos(&leaf, meta);
            pool.config
                .read_features
                .push("com.delphix:embedded_data".into());
            let mut view = pool.zpl(&cx, &[]).unwrap();
            assert!(view.read(&cx, 3, 0, 1027).is_err(), "case {case}");
            assert!(
                !reads.lock().unwrap().iter().any(|(at, _)| [
                    BASE as u64 + FIRST,
                    BASE as u64 + LAST
                ]
                .contains(at))
            );
            // A decoder failure does not poison earlier verified content, but
            // a corrupt parent cannot authorize even its first embedded block.
            if case == 10 {
                assert_eq!(view.read(&cx, 3, 0, 3).unwrap(), b"AAA");
            } else {
                assert!(view.read(&cx, 3, 0, 3).is_err());
            }
        }
    }
}
#[test]
fn sparse_eof_beyond_maxblkid_and_empty_reads_do_not_touch_file_blocks() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let (leaf, meta) = graph(Endian::Little, 0, 0, Arc::clone(&reads), None);
    let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
    view.stat(&cx, 7).unwrap();
    reads.lock().unwrap().clear();
    assert_eq!(view.read(&cx, 7, (1 << 40) + 2, 100).unwrap(), vec![0; 3]);
    assert_eq!(view.read(&cx, 6, 0, 100).unwrap(), [] as [u8; 0]);
    assert!(reads.lock().unwrap().is_empty());
    assert!(view.read(&cx, 3, 0, MAX_READ_BYTES + 1).is_err());
}
#[test]
fn symlinks_are_inspected_not_followed_and_path_errors_remain_errors() {
    let cx = Cx::for_testing();
    let (leaf, meta) = graph(Endian::Little, 1, 0, Arc::default(), None);
    let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
    let link = view.resolve(&cx, b"/link").unwrap();
    assert_eq!(view.readlink(&cx, link).unwrap(), b"file.bin");
    assert!(view.read(&cx, link, 0, 8).is_err());
    for path in [
        b"/link/child".as_slice(),
        b"/file.bin/.",
        b"/file.bin/",
        b"/../file.bin",
    ] {
        assert!(view.resolve(&cx, path).is_err());
    }
    assert_eq!(view.resolve(&cx, b"//./sub/./nested").unwrap(), 3);
    assert!(matches!(
        view.resolve(&cx, b"/absent"),
        Err(FfsError::NotFound(_))
    ));
    assert!(matches!(
        view.read(&cx, view.root, 0, 1),
        Err(FfsError::IsDirectory)
    ));
}
#[test]
fn type_parent_alias_and_future_generation_corruption_fail_whole_listing() {
    let cx = Cx::for_testing();
    for case in 1..=4 {
        let (leaf, meta) = graph(Endian::Little, 0, case, Arc::default(), None);
        let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
        assert!(view.list(&cx, view.root).is_err(), "{case}");
    }
}
#[test]
fn spill_corruption_and_data_cancellation_do_not_return_a_successful_prefix() {
    let cx = Cx::for_testing();
    let (leaf, meta) = graph(Endian::Little, 2, 5, Arc::default(), None);
    assert!(
        mos(&leaf, meta)
            .zpl(&cx, &[])
            .unwrap()
            .read(&cx, 3, 0, 1)
            .is_err()
    );
    let reads: Reads = Arc::default();
    let (leaf, meta) = graph(
        Endian::Little,
        0,
        0,
        Arc::clone(&reads),
        Some(BASE as u64 + LAST),
    );
    let mut view = mos(&leaf, meta).zpl(&cx, &[]).unwrap();
    assert!(matches!(
        view.read(&cx, 3, 0, 1027),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(
        reads
            .lock()
            .unwrap()
            .iter()
            .filter(|(at, _)| *at == BASE as u64 + LAST)
            .count(),
        1
    );
}
#[test]
fn registry_policy_and_dataset_root_mismatch_fail_before_file_reads() {
    let cx = Cx::for_testing();
    for case in [6, 7, 8] {
        let reads: Reads = Arc::default();
        let (leaf, meta) = graph(Endian::Little, 1, case, Arc::clone(&reads), None);
        assert!(mos(&leaf, meta).zpl(&cx, &[]).is_err(), "{case}");
        assert!(
            !reads
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| *at == BASE as u64 + FIRST)
        );
    }
    let (leaf, meta) = graph(Endian::Little, 0, 0, Arc::default(), None);
    assert!(matches!(
        mos(&leaf, meta).zpl(&cx, &[b"missing".to_vec()]),
        Err(FfsError::NotFound(_))
    ));
}
#[test]
fn dataset_views_do_not_reuse_mos_or_other_dataset_block_caches() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let (leaf, meta) = graph(Endian::Little, 0, 0, Arc::clone(&reads), None);
    let mut pool = mos(&leaf, meta);
    let mut first = pool.zpl(&cx, &[]).unwrap();
    let mut second = pool.zpl(&cx, &[]).unwrap();
    first.read(&cx, 3, 0, 1).unwrap();
    let before = reads
        .lock()
        .unwrap()
        .iter()
        .filter(|(at, _)| *at == BASE as u64 + FIRST)
        .count();
    second.read(&cx, 3, 0, 1).unwrap();
    assert_eq!(
        reads
            .lock()
            .unwrap()
            .iter()
            .filter(|(at, _)| *at == BASE as u64 + FIRST)
            .count(),
        before + 1
    );
    assert_eq!(pool.object(&cx, 1).unwrap().object_type(), 1);
    assert!(
        reads
            .lock()
            .unwrap()
            .iter()
            .all(|(at, len)| *at >= BASE as u64 && *at + *len as u64 <= (BASE + LENGTH) as u64)
    );
}

#[test]
fn zil_intent_log_replays_create_write_rename_truncate_and_remove_in_memory() {
    let cx = Cx::for_testing();
    let order = Endian::Little;
    let (leaf, _meta) = graph(order, 0, 0, Arc::default(), None);

    // Synthesize a 1024-byte ZIL block at ZIL_BLK (DATA_OFFSET + 0x36000) and attach its BP to view.zil_header.
    let zil_at = DATA_OFFSET + 0x36000;
    let mut zil_raw = vec![0_u8; 1024];
    let mut pos = 0_usize;
    let mut put_rec = |txtype: u64, txg: u64, seq: u64, body: &[u8]| {
        let reclen = (32 + body.len()).next_multiple_of(8);
        zil_raw[pos..pos + 8].copy_from_slice(&order.encode(txtype));
        zil_raw[pos + 8..pos + 16].copy_from_slice(&order.encode(reclen as u64));
        zil_raw[pos + 16..pos + 24].copy_from_slice(&order.encode(txg));
        zil_raw[pos + 24..pos + 32].copy_from_slice(&order.encode(seq));
        zil_raw[pos + 32..pos + 32 + body.len()].copy_from_slice(body);
        pos += reclen;
    };

    // 1. TX_CREATE (txtype = 1): create "/created.txt" (dir_obj = 2, file_obj = 50, mode = 0o100644)
    let mut create_body = vec![0_u8; 72];
    create_body[0..8].copy_from_slice(&order.encode(2)); // dir_obj
    create_body[8..16].copy_from_slice(&order.encode(50)); // file_obj
    create_body[16..24].copy_from_slice(&order.encode(0o100_644)); // mode
    create_body[24..32].copy_from_slice(&order.encode(1000)); // uid
    create_body[32..40].copy_from_slice(&order.encode(1000)); // gid
    create_body[40..48].copy_from_slice(&order.encode(10)); // gen
    create_body[48..56].copy_from_slice(&order.encode(1_700_000_100)); // crtime sec
    create_body.extend_from_slice(b"created.txt\0");
    put_rec(1, 62, 1, &create_body);

    // 2. TX_WRITE (txtype = 9): write "hello-zil-world" to file_obj = 50 at offset 0
    let payload = b"hello-zil-world";
    let mut write_body = vec![0_u8; 160];
    write_body[0..8].copy_from_slice(&order.encode(50)); // file_obj
    write_body[8..16].copy_from_slice(&order.encode(0)); // offset
    write_body[16..24].copy_from_slice(&order.encode(payload.len() as u64)); // length
    write_body.extend_from_slice(payload);
    put_rec(9, 62, 2, &write_body);

    // 3. TX_TRUNCATE (txtype = 10): truncate file_obj = 50 to length 9 ("hello-zil")
    let mut trunc_body = vec![0_u8; 24];
    trunc_body[0..8].copy_from_slice(&order.encode(50)); // file_obj
    trunc_body[8..16].copy_from_slice(&order.encode(9)); // offset = new size
    trunc_body[16..24].copy_from_slice(&order.encode(0)); // length = 0 means truncate to offset
    put_rec(10, 62, 3, &trunc_body);

    // 4. TX_RENAME (txtype = 8): rename "/empty" (dir 2) -> "/sub/renamed_empty" (dir 4)
    let mut rename_body = vec![0_u8; 16];
    rename_body[0..8].copy_from_slice(&order.encode(2)); // src_dir_obj
    rename_body[8..16].copy_from_slice(&order.encode(4)); // dst_dir_obj
    rename_body.extend_from_slice(b"empty\0renamed_empty\0");
    put_rec(8, 62, 4, &rename_body);

    // 5. TX_REMOVE (txtype = 5): remove "/alias.bin" from dir 2
    let mut remove_body = vec![0_u8; 8];
    remove_body[0..8].copy_from_slice(&order.encode(2)); // dir_obj
    remove_body.extend_from_slice(b"alias.bin\0");
    put_rec(5, 62, 5, &remove_body);

    // Set zil_chain_t trailer at end - 184: nused at trailer + 136
    let trailer_start = zil_raw.len() - 184;
    zil_raw[trailer_start + 136..trailer_start + 144].copy_from_slice(&order.encode(pos as u64));

    // Store the ZIL block into a new image with the ZIL header wired into OS[512..704]
    let (leaf_with_zil, meta_with_zil) = {
        let mut image = vec![0; BASE + LENGTH + 512];
        // Read existing graph bytes from `leaf` into `image`:
        let existing = leaf.read(&cx, 0, LENGTH).unwrap();
        image[BASE..BASE + LENGTH].copy_from_slice(&existing);
        let at_zil = BASE + zil_at as usize;
        image[at_zil..at_zil + zil_raw.len()].copy_from_slice(&zil_raw);
        let zil_bp = bp(&zil_raw, zil_at, 7, 0, 62, order, order);

        // Update OS[512..704] with ZilHeader and recompute DS bonus BP for OS:
        let at_os = BASE + OS as usize;
        let mut os_bytes = image[at_os..at_os + 1024].to_vec();
        os_bytes[512..520].copy_from_slice(&order.encode(62)); // claim_txg
        os_bytes[528..656].copy_from_slice(&zil_bp); // zh_log BP
        image[at_os..at_os + 1024].copy_from_slice(&os_bytes);

        let at_mos = BASE + MOS as usize;
        let mut mos_table = image[at_mos..at_mos + 16_384].to_vec();
        let mut ds = mos_table[1536 + 192..1536 + 192 + 320].to_vec();
        ds[128..256].copy_from_slice(&bp(&os_bytes, OS, 11, 0, 45, order, Endian::Big));
        mos_table[1536..2048].copy_from_slice(&node(16, 512, 1, 0, &ds, 16, order));
        image[at_mos..at_mos + 16_384].copy_from_slice(&mos_table);

        let mut meta_raw = node(10, 16_384, 1, 0, &[], 0, order);
        meta_raw[64..192].copy_from_slice(&bp(&mos_table, MOS, 10, 0, 50, order, order));
        let new_leaf = Leaf::from_device(
            &cx,
            Box::new(Memory {
                image,
                reads: Arc::default(),
                failure: None,
            }),
            BASE as u64,
            LENGTH as u64,
        )
        .unwrap();
        (new_leaf, Dnode::parse(&meta_raw, order).unwrap())
    };

    let mut pool = mos(&leaf_with_zil, meta_with_zil);
    let mut view = pool.zpl(&cx, &[]).unwrap();
    assert!(view.zil_header.has_work());
    assert!(view.zil_replay_stats().is_none());
    // Before replay_zil:
    assert!(matches!(
        view.resolve(&cx, b"/created.txt"),
        Err(FfsError::NotFound(_))
    ));
    assert_eq!(view.resolve(&cx, b"/alias.bin").unwrap(), 3);
    assert_eq!(view.resolve(&cx, b"/empty").unwrap(), 6);

    // Replay ZIL:
    let stats = view.replay_zil(&cx).unwrap();
    assert_eq!(view.zil_replay_stats(), Some(&stats));
    assert_eq!(stats.blocks_visited, 1);
    assert_eq!(stats.records_replayed, 5);
    assert_eq!(stats.last_txg, 62);
    assert_eq!(stats.last_seq, 5);

    // Verify TX_CREATE + TX_WRITE + TX_TRUNCATE on /created.txt:
    let created_obj = view.resolve(&cx, b"/created.txt").unwrap();
    assert_eq!(created_obj, 50);
    let (meta50, _) = view.stat(&cx, created_obj).unwrap();
    assert_eq!(meta50.size, 9);
    assert_eq!(view.read(&cx, created_obj, 0, 64).unwrap(), b"hello-zil");

    // Verify TX_REMOVE on /alias.bin:
    assert!(matches!(
        view.resolve(&cx, b"/alias.bin"),
        Err(FfsError::NotFound(_))
    ));

    // Verify TX_RENAME of /empty -> /sub/renamed_empty:
    assert!(matches!(
        view.resolve(&cx, b"/empty"),
        Err(FfsError::NotFound(_))
    ));
    let renamed_obj = view.resolve(&cx, b"/sub/renamed_empty").unwrap();
    assert_eq!(renamed_obj, 6);
    let (meta6, _) = view.stat(&cx, renamed_obj).unwrap();
    assert_eq!(meta6.parent, 4);
}

mod mount;

mod mirror;

mod raidz;

mod gang;
mod xattrs;
