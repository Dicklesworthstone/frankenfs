use super::*;
use crate::reader::dmu::tests::embedded_pointer;
use crate::reader::{Leaf, VdevConfig};
use ffs_block::ByteDevice;
use ffs_ondisk::zfs::{DATA_OFFSET, Endian, LABEL_BYTES, checksum};
use ffs_ondisk::zfs_dmu::Dnode;
use ffs_types::ByteOffset;
use std::sync::{Arc, Mutex};

const BASE: usize = 1024;
const LENGTH: usize = 8 * 1024 * 1024;
const MOS: u64 = DATA_OFFSET + 0x10000;
const MAP: u64 = DATA_OFFSET + 0x15000;
const OLDER_ROOT: u64 = DATA_OFFSET + 0x20000;
type Reads = Arc<Mutex<Vec<u64>>>;

fn w16(raw: &mut [u8], at: usize, word: u16, order: Endian) {
    let bytes = match order {
        Endian::Little => word.to_le_bytes(),
        Endian::Big => word.to_be_bytes(),
    };
    raw[at..at + 2].copy_from_slice(&bytes);
}
fn w64(raw: &mut [u8], at: usize, word: u64, order: Endian) {
    raw[at..at + 8].copy_from_slice(&order.encode(word));
}
fn node(kind: u8, size: usize, level: u8, last: u64, order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = level;
    raw[3] = 1;
    raw[7] = 1;
    w16(&mut raw, 8, (size / 512) as u16, order);
    w64(&mut raw, 16, last, order);
    raw
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
    let mut words = [0_u64; 16];
    words[0] = data.len() as u64 / 512;
    words[1] = (at - DATA_OFFSET) / 512;
    words[6] = (data.len() as u64 / 512 - 1)
        | ((data.len() as u64 / 512 - 1) << 16)
        | (2 << 32)
        | (7 << 40)
        | (u64::from(kind) << 48)
        | (u64::from(level) << 56)
        | (u64::from(payload == Endian::Little) << 63);
    words[10] = birth;
    words[12..].copy_from_slice(&checksum(data, 7, payload).unwrap());
    words
        .into_iter()
        .flat_map(|word| order.encode(word))
        .collect()
}
fn bonus(mut node: Vec<u8>, kind: u8, data: &[u8], order: Endian) -> Vec<u8> {
    node[4] = kind;
    w16(&mut node, 10, data.len() as u16, order);
    node[192..192 + data.len()].copy_from_slice(data);
    node
}
fn micro(entries: &[(&[u8], u64)], norm: u64, order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 512];
    w64(&mut raw, 0, (1_u64 << 63) + 3, order);
    w64(&mut raw, 8, 42, order);
    w64(&mut raw, 16, norm, order);
    for (i, (name, value)) in entries.iter().enumerate() {
        let at = 64 + i * 64;
        w64(&mut raw, at, *value, order);
        raw[at + 14..at + 14 + name.len()].copy_from_slice(name);
    }
    raw
}
fn metadata(kind: u64, size: u64, link: Option<&[u8]>, order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 264 + link.map_or(0, <[u8]>::len)];
    for (at, value) in [
        (64, 2),
        (72, (kind << 12) | 0o644),
        (80, size),
        (88, 2),
        (96, if kind == 4 { 2 } else { 1 }),
        (128, 1000),
        (136, 1000),
    ] {
        w64(&mut raw, at, value, order);
    }
    if let Some(link) = link {
        raw[264..].copy_from_slice(link);
    }
    raw
}

struct Image {
    bytes: Vec<u8>,
    order: Endian,
    table: Vec<u8>,
    meta: Dnode,
}
impl Image {
    fn new(order: Endian, case: u8) -> Self {
        let other = if order == Endian::Little {
            Endian::Big
        } else {
            Endian::Little
        };
        let mut image = Self {
            bytes: vec![0; BASE + LENGTH + 512],
            order,
            table: vec![0; 16384],
            meta: Dnode::parse(&node(10, 16384, 1, 0, order), order).unwrap(),
        };
        image.bytes[..BASE].fill(0xa5);
        image.bytes[BASE + LENGTH..].fill(0x5a);
        let roots: Vec<_> = [18_u64, 28, 60]
            .into_iter()
            .enumerate()
            .map(|(state, birth)| image.filesystem(state, birth, other, case))
            .collect();
        image.map(
            1,
            1,
            DATA_OFFSET + 0x14000,
            &[(b"root_dataset", 2)],
            0,
            other,
        );
        let origin = if matches!(case, 15..=18) { 7 } else { 0 };
        let mut dir = vec![0; 256];
        w64(&mut dir, 8, 3, order);
        w64(&mut dir, 24, origin, order);
        image.set_node(2, &bonus(node(12, 512, 1, 0, order), 12, &dir, order));
        let names = match case {
            1 => vec![(b"before".as_slice(), 5), (b"after".as_slice(), 5)],
            2 => vec![(b"before".as_slice(), 5)],
            3 => vec![
                (b"before".as_slice(), 5),
                (b"after".as_slice(), 6),
                (b"extra".as_slice(), 9),
            ],
            14 => Vec::new(),
            _ => vec![(b"before".as_slice(), 5), (b"after".as_slice(), 6)],
        };
        image.map(4, if case == 4 { 20 } else { 14 }, MAP, &names, 2, other);
        for (id, state, creation, previous, previous_txg, next, names) in [
            (
                3,
                2,
                10,
                if case == 14 { 0 } else { 6 },
                if case == 14 { 0 } else { 30 },
                0,
                4,
            ),
            (5, 0, 20, origin, u64::from(origin != 0), 6, 0),
            (6, 1, 30, 5, 20, 3, 0),
        ] {
            let mut data = vec![0; 320];
            for (at, value) in [
                (0, 2),
                (8, previous),
                (16, previous_txg),
                (24, next),
                (32, names),
                (40, u64::from(id != 3)),
                (48, 1_700_000_000 + creation),
                (56, creation),
                (72, 16384),
                (112, 1000 + id),
                (120, 4),
            ] {
                w64(&mut data, at, value, order);
            }
            data[128..256].copy_from_slice(&roots[state]);
            if id == 6 {
                for (which, at, value) in [
                    (5, 0, 99),
                    (6, 24, 5),
                    (7, 56, 31),
                    (8, 112, 1005),
                    (9, 32, 4),
                    (10, 40, 0),
                    (11, 8, 6),
                    (12, 120, 1),
                    (19, 120, 0x1_0004),
                ] {
                    if case == which {
                        w64(&mut data, at, value, order);
                    }
                }
            }
            if id == 5 && case == 13 {
                w64(&mut data, 208, 21, order);
            }
            image.set_node(id, &bonus(node(16, 512, 1, 0, order), 16, &data, order));
        }
        if origin != 0 {
            let mut data = vec![0; 320];
            for (at, value) in [
                (0, 99),
                (24, 9),
                (40, 2),
                (56, 1),
                (112, 999),
                (120, 4),
                (256, 8),
            ] {
                w64(&mut data, at, value, order);
            }
            if case == 16 {
                w64(&mut data, 56, 2, order);
            }
            if case == 17 {
                w64(&mut data, 40, 3, order);
            }
            image.set_node(7, &bonus(node(16, 512, 1, 0, order), 16, &data, order));
            image.map(
                8,
                37,
                DATA_OFFSET + 0x16000,
                &[(
                    if case == 18 { b"6" } else { b"5" },
                    if case == 18 { 6 } else { 5 },
                )],
                0,
                order,
            );
        }
        image.finish();
        image
    }
    fn store(&mut self, at: u64, raw: &[u8]) {
        let at = BASE + at as usize;
        self.bytes[at..at + raw.len()].copy_from_slice(raw);
    }
    fn set_node(&mut self, id: u64, raw: &[u8]) {
        self.table[id as usize * 512..(id as usize + 1) * 512].copy_from_slice(raw);
    }
    fn map(
        &mut self,
        id: u64,
        kind: u8,
        at: u64,
        entries: &[(&[u8], u64)],
        norm: u64,
        payload: Endian,
    ) {
        let raw = micro(entries, norm, payload);
        let mut dn = node(kind, 512, 1, 0, self.order);
        dn[64..192].copy_from_slice(&pointer(&raw, at, kind, 0, 70, self.order, payload));
        self.store(at, &raw);
        self.set_node(id, &dn);
    }
    fn filesystem(&mut self, state: usize, birth: u64, order: Endian, case: u8) -> Vec<u8> {
        let at = DATA_OFFSET + 0x30000 + state as u64 * 0x10000;
        let mut table = vec![0; 16384];
        let master = micro(&[(b"VERSION", 4), (b"ROOT", 2)], 0, order);
        let mut dn = node(21, 512, 1, 0, order);
        dn[64..192].copy_from_slice(&pointer(
            &master,
            at + 0x4000,
            21,
            0,
            birth - 2,
            order,
            order,
        ));
        table[512..1024].copy_from_slice(&dn);
        self.store(at + 0x4000, &master);
        let mut entries = vec![
            (b"file".as_slice(), (8_u64 << 60) | 3),
            (b"link".as_slice(), (10_u64 << 60) | 4),
        ];
        if state == 0 {
            entries.push((b"gone", (8_u64 << 60) | 5));
        }
        let directory = micro(&entries, 0, order);
        let mut dn = bonus(
            node(20, 512, 1, 0, order),
            17,
            &metadata(4, 2 + entries.len() as u64, None, order),
            order,
        );
        dn[64..192].copy_from_slice(&pointer(
            &directory,
            at + 0x4200,
            20,
            0,
            birth - 2,
            order,
            order,
        ));
        table[1024..1536].copy_from_slice(&dn);
        self.store(at + 0x4200, &directory);
        let mut indirect = vec![0; 4096];
        let a = vec![b'A' + state as u8 * 2; 512];
        let b = vec![b'B' + state as u8 * 2; 512];
        indirect[..128].copy_from_slice(&pointer(
            &a,
            at + 0x6000,
            19,
            0,
            if state == 0 && case == 20 {
                19
            } else {
                birth - 4
            },
            order,
            order,
        ));
        indirect[256..384].copy_from_slice(&pointer(
            &b,
            at + 0x6800,
            19,
            0,
            birth - 4,
            order,
            order,
        ));
        if matches!(case, 21 | 22) {
            indirect[..128].copy_from_slice(&embedded_pointer(
                b'A' + state as u8 * 2,
                if case == 22 && state == 0 {
                    21
                } else {
                    birth - 4
                },
                order,
                self.order,
            ));
            indirect[256..384].copy_from_slice(&embedded_pointer(
                b'B' + state as u8 * 2,
                birth - 4,
                order,
                self.order,
            ));
        }
        self.store(at + 0x5000, &indirect);
        self.store(at + 0x6000, &a);
        self.store(at + 0x6800, &b);
        let size = [2049, 600, 900][state];
        let mut dn = bonus(
            node(19, 512, 2, 2, order),
            17,
            &metadata(8, size, None, order),
            order,
        );
        dn[64..192].copy_from_slice(&pointer(
            &indirect,
            at + 0x5000,
            19,
            1,
            birth - 3,
            order,
            order,
        ));
        table[1536..2048].copy_from_slice(&dn);
        table[2048..2560].copy_from_slice(&bonus(
            node(19, 512, 1, 0, order),
            17,
            &metadata(10, 4, Some(b"file"), order),
            order,
        ));
        table[2560..3072].copy_from_slice(&bonus(
            node(19, 512, 1, 0, order),
            17,
            &metadata(8, 0, None, order),
            order,
        ));
        let mut os = vec![0; 1024];
        let mut meta = node(10, 16384, 1, 0, order);
        meta[64..192].copy_from_slice(&pointer(&table, at, 10, 0, birth - 1, order, order));
        os[..512].copy_from_slice(&meta);
        w64(&mut os, 704, 2, order);
        self.store(at, &table);
        let root_at = OLDER_ROOT + state as u64 * 4096;
        self.store(root_at, &os);
        pointer(&os, root_at, 11, 0, birth, self.order, order)
    }
    fn finish(&mut self) {
        let table = self.table.clone();
        self.store(MOS, &table);
        let mut meta = node(10, 16384, 1, 0, self.order);
        meta[64..192].copy_from_slice(&pointer(&table, MOS, 10, 0, 80, self.order, self.order));
        self.meta = Dnode::parse(&meta, self.order).unwrap();
    }
    fn open(self, reads: Reads, failure: Option<u64>) -> (Leaf, Dnode) {
        let leaf = Leaf::from_device(
            &Cx::for_testing(),
            Box::new(Memory {
                bytes: self.bytes,
                reads,
                failure,
            }),
            BASE as u64,
            LENGTH as u64,
        )
        .unwrap();
        (leaf, self.meta)
    }
}
struct Memory {
    bytes: Vec<u8>,
    reads: Reads,
    failure: Option<u64>,
}
impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, _: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push(offset.0);
        if self.failure == Some(offset.0) {
            return Err(FfsError::Cancelled);
        }
        let start = offset.0 as usize;
        let end = start
            .checked_add(out.len())
            .ok_or_else(|| corrupt("test range overflow"))?;
        out.copy_from_slice(
            self.bytes
                .get(start..end)
                .ok_or_else(|| corrupt("short test image"))?,
        );
        Ok(())
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("snapshot read wrote to backing image")
    }
    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("snapshot read flushed backing image")
    }
}
fn pool(leaf: &Leaf, meta: Dnode) -> Objects {
    Objects {
        pool: leaf.clone().into(),
        meta,
        config: VdevConfig {
            pool_guid: 123,
            top_guid: 999,
            version: 5000,
            txg: 90,
            ashift: 9,
            id: 0,
            allocated_bytes: LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES,
            read_features: Vec::new(),
            raidz_members: None,
        },
        txg: 100,
        root_birth: 90,
        cache: VecDeque::new(),
        cached_bytes: 0,
    }
}
fn old_bytes() -> Vec<u8> {
    let mut out = vec![b'A'; 512];
    out.extend_from_slice(&[0; 512]);
    out.extend_from_slice(&[b'B'; 512]);
    out.resize(2049, 0);
    out
}

#[test]
fn snapshot_names_lineage_and_historical_roots_are_independent_of_live_cache() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let reads: Reads = Arc::default();
        let (leaf, meta) = Image::new(order, 0).open(Arc::clone(&reads), None);
        let mut pool = pool(&leaf, meta);
        let rows = pool.snapshots(&cx, &[]).unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row.name.as_slice())
                .collect::<Vec<_>>(),
            [b"after".as_slice(), b"before"]
        );
        assert_eq!(
            (
                rows[0].object,
                rows[0].guid,
                rows[0].creation_txg,
                rows[0].root_birth
            ),
            (6, 1006, 30, 28)
        );
        let mut live = pool.zpl(&cx, &[]).unwrap();
        let mut before = pool.zpl_snapshot(&cx, &[], b"before").unwrap();
        let mut after = pool.zpl_snapshot(&cx, &[], b"after").unwrap();
        assert_eq!(
            (live.dataset_guid, before.dataset_guid, after.dataset_guid),
            (1003, 1005, 1006)
        );
        assert_eq!(
            (live.view_txg(), before.view_txg(), after.view_txg()),
            (100, 20, 30)
        );
        for _ in 0..2 {
            assert_eq!(live.resolve(&cx, b"/file").unwrap(), 3);
            assert_eq!(before.resolve(&cx, b"/file").unwrap(), 3);
            assert_eq!(before.read(&cx, 3, 0, 4096).unwrap(), old_bytes());
            assert_eq!(
                (
                    live.read(&cx, 3, 0, 1).unwrap(),
                    after.read(&cx, 3, 0, 1).unwrap()
                ),
                (vec![b'E'], vec![b'C'])
            );
            assert_eq!(before.resolve(&cx, b"/gone").unwrap(), 5);
            assert!(matches!(
                live.resolve(&cx, b"/gone"),
                Err(FfsError::NotFound(_))
            ));
            assert_eq!(before.readlink(&cx, 4).unwrap(), b"file");
            assert_eq!(before.read(&cx, 3, 2049, 1).unwrap(), [] as [u8; 0]);
            assert_eq!(
                before.read(&cx, 3, 510, 1029).unwrap(),
                old_bytes()[510..1539]
            );
        }
        assert!(matches!(
            pool.zpl_snapshot(&cx, &[], b"BEFORE"),
            Err(FfsError::NotFound(_))
        ));
        assert!(
            reads
                .lock()
                .unwrap()
                .iter()
                .all(|at| *at >= BASE as u64 && *at < (BASE + LENGTH) as u64)
        );
    }
}

#[test]
fn snapshot_inventory_rejects_aliases_missing_names_stale_links_and_future_roots() {
    let cx = Cx::for_testing();
    for case in 1..=13 {
        let (leaf, meta) = Image::new(Endian::Little, case).open(Arc::default(), None);
        assert!(
            pool(&leaf, meta).snapshots(&cx, &[]).is_err(),
            "case {case}"
        );
    }
    let (leaf, meta) = Image::new(Endian::Little, 19).open(Arc::default(), None);
    assert!(pool(&leaf, meta).zpl_snapshot(&cx, &[], b"after").is_err());
}

#[test]
fn snapshot_empty_map_and_native_origin_branch_are_distinct() {
    let cx = Cx::for_testing();
    let (leaf, meta) = Image::new(Endian::Little, 14).open(Arc::default(), None);
    assert!(pool(&leaf, meta).snapshots(&cx, &[]).unwrap().is_empty());
    let (leaf, meta) = Image::new(Endian::Little, 15).open(Arc::default(), None);
    assert_eq!(pool(&leaf, meta).snapshots(&cx, &[]).unwrap().len(), 2);
    for case in 16..=18 {
        let (leaf, meta) = Image::new(Endian::Little, case).open(Arc::default(), None);
        assert!(
            pool(&leaf, meta).snapshots(&cx, &[]).is_err(),
            "origin case {case}"
        );
    }
}

#[test]
fn snapshot_read_rejects_younger_children_and_propagates_live_io_cancellation() {
    let cx = Cx::for_testing();
    let (leaf, meta) = Image::new(Endian::Little, 20).open(Arc::default(), None);
    let mut before = pool(&leaf, meta).zpl_snapshot(&cx, &[], b"before").unwrap();
    assert!(before.read(&cx, 3, 0, 2049).is_err());
    let failure = BASE as u64 + DATA_OFFSET + 0x36800;
    let reads: Reads = Arc::default();
    let (leaf, meta) = Image::new(Endian::Little, 0).open(Arc::clone(&reads), Some(failure));
    let mut before = pool(&leaf, meta).zpl_snapshot(&cx, &[], b"before").unwrap();
    assert!(matches!(
        before.read(&cx, 3, 0, 2049),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(
        reads
            .lock()
            .unwrap()
            .iter()
            .filter(|at| **at == failure)
            .count(),
        1
    );
    let (leaf, meta) =
        Image::new(Endian::Little, 0).open(Arc::default(), Some(BASE as u64 + OLDER_ROOT));
    assert!(matches!(
        pool(&leaf, meta).snapshots(&cx, &[]),
        Err(FfsError::Cancelled)
    ));
}

#[test]
fn snapshot_component_validation_and_corrupt_data_never_select_head_fallback() {
    let cx = Cx::for_testing();
    let mut image = Image::new(Endian::Little, 0);
    image.bytes[BASE + DATA_OFFSET as usize + 0x36800] ^= 1;
    let (leaf, meta) = image.open(Arc::default(), None);
    let mut pool = pool(&leaf, meta);
    for name in [b"".as_slice(), b"..", b"a/b", b"a@b", b"a#b", b"a\0b"] {
        assert!(pool.zpl_snapshot(&cx, &[], name).is_err());
    }
    let mut old = pool.zpl_snapshot(&cx, &[], b"before").unwrap();
    assert!(old.read(&cx, 3, 0, 2049).is_err());
    let mut live = pool.zpl(&cx, &[]).unwrap();
    assert_eq!(live.read(&cx, 3, 0, 1).unwrap(), b"E");
}

#[test]
fn embedded_snapshot_contents_are_historical_and_never_read_physical_payloads() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let reads: Reads = Arc::default();
        let (leaf, meta) = Image::new(order, 21).open(Arc::clone(&reads), None);
        let mut selected = pool(&leaf, meta);
        selected
            .config
            .read_features
            .push("com.delphix:embedded_data".into());
        let mut live = selected.zpl(&cx, &[]).unwrap();
        let mut before = selected.zpl_snapshot(&cx, &[], b"before").unwrap();
        let mut after = selected.zpl_snapshot(&cx, &[], b"after").unwrap();
        for _ in 0..2 {
            assert_eq!(live.read(&cx, 3, 0, 8).unwrap(), b"EEEEEEEE");
            assert_eq!(
                before.read(&cx, 3, 510, 1029).unwrap(),
                old_bytes()[510..1539]
            );
            assert_eq!(after.read(&cx, 3, 0, 8).unwrap(), b"CCCCCCCC");
            assert_eq!(before.read(&cx, 3, 0, 4096).unwrap(), old_bytes());
        }
        assert!(!reads.lock().unwrap().iter().any(|at| {
            [0x36000, 0x36800, 0x46000, 0x46800, 0x56000, 0x56800]
                .iter()
                .any(|relative| *at == BASE as u64 + DATA_OFFSET + relative)
        }));

        let (leaf, meta) = Image::new(order, 22).open(Arc::default(), None);
        let mut pool = pool(&leaf, meta);
        pool.config
            .read_features
            .push("com.delphix:embedded_data".into());
        let mut before = pool.zpl_snapshot(&cx, &[], b"before").unwrap();
        assert!(before.read(&cx, 3, 0, 1).is_err());
        assert_eq!(
            pool.zpl(&cx, &[]).unwrap().read(&cx, 3, 0, 1).unwrap(),
            b"E"
        );
    }
}

mod mount;

mod mirror;

mod raidz;
