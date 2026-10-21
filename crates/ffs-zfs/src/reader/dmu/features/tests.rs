//! Policy adversaries and constructed checked-MOS graphs; not native-pool proof.
use super::*;
use crate::reader::{ByteOffset, Leaf, Pool, RootBlock, VdevConfig};
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_ondisk::zfs::{BlockPointer, DATA_OFFSET, Endian, Uberblock, checksum};
use std::sync::{Arc, Mutex};

fn entry(name: &str, count: u64) -> Entry {
    Entry {
        name: name.as_bytes().to_vec(),
        integer_bytes: 8,
        values: vec![count],
        collision: 0,
    }
}

#[test]
fn unknown_inactive_reads_and_active_write_only_features_follow_native_ro_rules() {
    let cx = Cx::for_testing();
    for count in [0, 1, u64::MAX] {
        assert!(admit(&cx, &[], &[entry("example.org:new_writer", count)], &[]).is_ok());
        let result = admit(&cx, &[entry("example.org:new_reader", count)], &[], &[]);
        if count == 0 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(FfsError::UnsupportedFeature(_))));
        }
    }
}

#[test]
fn existing_native_codecs_and_dnodes_accept_enabled_zero_count_dependencies() {
    let cx = Cx::for_testing();
    for name in [
        "org.open-zfs:large_blocks",
        "org.zfsonlinux:large_dnode",
        "org.illumos:sha512",
        "org.freebsd:zstd_compress",
    ] {
        for count in [0, 1, u64::MAX] {
            assert!(admit(&cx, &[entry(name, count)], &[], &[]).is_err());
            assert!(
                admit(
                    &cx,
                    &[
                        entry(name, count),
                        entry("com.delphix:extensible_dataset", 0)
                    ],
                    &[],
                    &[]
                )
                .is_ok()
            );
        }
    }
}

#[test]
fn known_read_features_cannot_evade_admission_in_the_write_catalog() {
    let cx = Cx::for_testing();
    for name in [
        "com.datto:encryption",
        "org.openzfs:blake3",
        "org.openzfs:draid",
        "org.illumos:lz4_compress",
        "com.delphix:embedded_data",
    ] {
        for count in [0, 1] {
            assert!(matches!(
                admit(&cx, &[], &[entry(name, count)], &[]),
                Err(FfsError::Corruption { .. })
            ));
        }
    }
    assert!(admit(&cx, &[entry("com.delphix:async_destroy", 0)], &[], &[]).is_err());
}

#[test]
fn duplicates_and_mistyped_counts_never_become_inactive_features() {
    let cx = Cx::for_testing();
    assert!(
        admit(
            &cx,
            &[
                entry("org.illumos:lz4_compress", 0),
                entry("org.illumos:lz4_compress", 1)
            ],
            &[],
            &[]
        )
        .is_err()
    );
    assert!(admit(&cx, &[entry("test:new", 0)], &[entry("test:new", 0)], &[]).is_err());
    for width in [1, 2, 4] {
        let mut row = entry("test:new", 0);
        row.integer_bytes = width;
        assert!(admit(&cx, &[row], &[], &[]).is_err());
    }
    for values in [vec![], vec![0, 0], vec![0, u64::MAX]] {
        let mut row = entry("test:new", 0);
        row.values = values;
        assert!(admit(&cx, &[row], &[], &[]).is_err());
    }
}

#[test]
fn native_guid_grammar_and_catalog_work_are_bounded() {
    let cx = Cx::for_testing();
    for name in [
        "test.no_colon",
        "test:a:b",
        "Test:a",
        "test:a-b",
        "test:a.b",
        "test:a\0",
    ] {
        assert!(admit(&cx, &[entry(name, 0)], &[], &[]).is_err());
    }
    assert!(guid(b"org.open-zfs:large_blocks").is_ok());
    assert!(guid(&[0xff, b':', b'a']).is_err());
    assert!(guid(format!("test:{}", "a".repeat(MAX_GUID_BYTES)).as_bytes()).is_err());
    let mut rows: Vec<_> = (0..MAX_FEATURES)
        .map(|i| entry(&format!("test:writer_{i}"), 1))
        .collect();
    assert!(admit(&cx, &[], &rows, &[]).is_ok());
    rows.push(entry("test:one_too_many", 1));
    assert!(matches!(
        admit(&cx, &[], &rows, &[]),
        Err(FfsError::UnsupportedFeature(_))
    ));
}

#[test]
fn bootstrap_labels_and_selected_mos_must_agree_on_active_features() {
    let cx = Cx::for_testing();
    let labels = vec!["com.delphix:embedded_data".into()];
    assert!(admit(&cx, &[entry("com.delphix:embedded_data", 1)], &[], &labels).is_ok());
    assert!(admit(&cx, &[entry("com.delphix:embedded_data", 1)], &[], &[]).is_err());
    assert!(admit(&cx, &[entry("com.delphix:embedded_data", 0)], &[], &labels).is_err());
    assert!(admit(&cx, &[], &[], &labels).is_err());
    assert!(
        admit(
            &cx,
            &[entry("com.delphix:embedded_data", 1)],
            &[],
            &[labels[0].clone(), labels[0].clone()]
        )
        .is_err()
    );
    // lz4 is read-required but not ZFEATURE_FLAG_MOS in the pinned registry.
    assert!(admit(&cx, &[entry("org.illumos:lz4_compress", 1)], &[], &[]).is_ok());
}

#[test]
fn hole_birth_bootstrap_and_mos_use_the_same_registry_without_admitting_unknown_labels() {
    let cx = Cx::for_testing();
    let labels = vec!["com.delphix:hole_birth".into()];
    let write = [entry("com.delphix:enabled_txg", 0)];
    assert!(admit(&cx, &[entry("com.delphix:hole_birth", 1)], &write, &labels).is_ok());
    assert!(admit(&cx, &[entry("com.delphix:hole_birth", 1)], &[], &labels).is_err());
    assert!(admit(&cx, &[entry("com.delphix:hole_birth", 1)], &write, &[]).is_err());
    assert!(admit(&cx, &[entry("com.delphix:hole_birth", 0)], &write, &labels).is_err());
    assert!(admit(&cx, &[entry("com.delphix:hole_birth", 0)], &write, &[]).is_ok());
    for name in [
        "com.delphix:hole_birth",
        "com.delphix:embedded_data",
        "org.illumos:lz4_compress",
    ] {
        assert!(crate::reader::supported_read_feature(
            name,
            &Value::Boolean(true)
        ));
        for value in [Value::Boolean(false), Value::Unsigned(1)] {
            assert!(!crate::reader::supported_read_feature(name, &value));
        }
    }
    for name in [
        "test:future",
        "com.delphix:enabled_txg",
        "com.datto:encryption",
        "org.open-zfs:large_blocks",
    ] {
        assert!(!crate::reader::supported_read_feature(
            name,
            &Value::Boolean(true)
        ));
    }
}

#[test]
fn write_only_dependencies_must_be_present_but_need_not_be_active() {
    let cx = Cx::for_testing();
    let rows = [entry("com.delphix:log_spacemap", 1)];
    assert!(admit(&cx, &[], &rows, &[]).is_err());
    assert!(
        admit(
            &cx,
            &[],
            &[
                entry("com.delphix:log_spacemap", 1),
                entry("com.delphix:spacemap_v2", 0)
            ],
            &[]
        )
        .is_ok()
    );
}

const BASE: u64 = 1024;
const LENGTH: u64 = 8 * 1024 * 1024;
const TABLE: u64 = DATA_OFFSET + 0x10000;
const DIRECTORY: u64 = DATA_OFFSET + 0x14000;
const READ: u64 = DIRECTORY + 512;
const WRITE: u64 = READ + 512;
const DESCRIPTIONS: u64 = WRITE + 512;
type Reads = Arc<Mutex<Vec<u64>>>;

struct Memory {
    blocks: BTreeMap<u64, Vec<u8>>,
    reads: Reads,
    failure: Option<(u64, bool)>,
}
impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 {
        BASE + LENGTH
    }
    fn read_exact_at(&self, _cx: &Cx, at: ByteOffset, output: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push(at.0);
        if let Some((offset, cancel)) = self.failure
            && at.0 == BASE + offset
        {
            return Err(if cancel {
                FfsError::Cancelled
            } else {
                corrupt("injected feature I/O failure")
            });
        }
        let (base, data) = self
            .blocks
            .range(..=at.0)
            .next_back()
            .ok_or_else(|| corrupt("unmapped test read"))?;
        let start = usize::try_from(at.0 - *base).unwrap();
        let bytes = data
            .get(start..start + output.len())
            .ok_or_else(|| corrupt("out-of-bounds test read"))?;
        output.copy_from_slice(bytes);
        Ok(())
    }
    fn write_all_at(&self, _cx: &Cx, _at: ByteOffset, _bytes: &[u8]) -> Result<()> {
        panic!("read admission wrote the backing")
    }
    fn sync(&self, _cx: &Cx) -> Result<()> {
        panic!("read admission flushed the backing")
    }
}

fn pointer(bytes: &[u8], at: u64, kind: u8, birth: u64, order: Endian) -> Vec<u8> {
    let sectors = bytes.len() as u64 / 512;
    let mut words = [0; 16];
    words[0] = sectors;
    words[1] = (at - DATA_OFFSET) / 512;
    words[6] = (sectors - 1)
        | ((sectors - 1) << 16)
        | (2 << 32)
        | (7 << 40)
        | (u64::from(kind) << 48)
        | (u64::from(order == Endian::Little) << 63);
    words[10] = birth;
    words[12..].copy_from_slice(&checksum(bytes, 7, order).unwrap());
    words
        .into_iter()
        .flat_map(|word| order.encode(word))
        .collect()
}
fn node(bytes: &[u8], at: u64, kind: u8, order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = 1;
    raw[3] = 1;
    raw[7] = 1;
    let sectors = (bytes.len() / 512) as u16;
    raw[8..10].copy_from_slice(&match order {
        Endian::Little => sectors.to_le_bytes(),
        Endian::Big => sectors.to_be_bytes(),
    });
    raw[64..192].copy_from_slice(&pointer(bytes, at, kind, 20, order));
    raw
}
fn micro(rows: &[(&[u8], u64)], order: Endian) -> Vec<u8> {
    assert!(rows.len() <= 7);
    let mut raw = vec![0; 512];
    raw[..8].copy_from_slice(&order.encode((1 << 63) + 3));
    for (i, (name, count)) in rows.iter().enumerate() {
        let at = 64 + i * 64;
        raw[at..at + 8].copy_from_slice(&order.encode(*count));
        raw[at + 14..at + 14 + name.len()].copy_from_slice(name);
    }
    raw
}

// Both existing complete ZPL graph families use native root_dataset object 2
// and reserve MOS slots 29..31 plus the gap between their pool and child maps.
// Install real checksum-protected ZAPs, never a production admission bypass.
// Their mirror/RAIDZ/gang builders already copy/re-encode this same block graph.
pub(in crate::reader) const GRAPH_DIRECTORY: &[(&[u8], u64)] = &[
    (b"root_dataset", 2),
    (b"features_for_read", 29),
    (b"features_for_write", 30),
    (b"feature_descriptions", 31),
];

pub(in crate::reader) fn install_graph_catalogs(
    table: &mut [u8],
    order: Endian,
) -> Vec<(u64, Vec<u8>)> {
    assert_eq!(table.len(), 16 * 1024);
    let read = micro(
        &[
            (b"org.illumos:lz4_compress", 1),
            (b"com.delphix:embedded_data", 1),
        ],
        order,
    );
    let mut blocks = Vec::new();
    for (id, at, bytes) in [
        (29, DATA_OFFSET + 0x14400, read),
        (30, DATA_OFFSET + 0x14600, micro(&[], order)),
        (31, DATA_OFFSET + 0x14800, micro(&[], order)),
    ] {
        let slot = &mut table[id * 512..(id + 1) * 512];
        assert!(
            slot.iter().all(|byte| *byte == 0),
            "fixture catalog slot already used"
        );
        slot.copy_from_slice(&node(&bytes, at, 196, order));
        blocks.push((at, bytes));
    }
    blocks
}

fn fixture(
    order: Endian,
    count: u64,
    case: u8,
    failure: Option<(u64, bool)>,
) -> (Pool, RootBlock, Reads) {
    let mut rows: Vec<(&[u8], u64)> = vec![
        (b"features_for_read", 2),
        (b"features_for_write", 3),
        (b"feature_descriptions", 4),
    ];
    if case == 1 {
        rows.pop();
    }
    if case == 2 {
        rows[1].1 = 2;
    }
    if case == 4 {
        rows = GRAPH_DIRECTORY.to_vec();
    }
    let directory = micro(&rows, order);
    let read_name: &[u8] = if case == 5 {
        b"com.delphix:hole_birth"
    } else {
        b"test:future"
    };
    let read = micro(&[(read_name, count)], order);
    let write = if case == 5 {
        micro(&[(b"com.delphix:enabled_txg", 0)], order)
    } else {
        micro(&[(b"test:writer_only", u64::MAX)], order)
    };
    let descriptions = micro(&[], order);
    let mut blocks = BTreeMap::new();
    let mut table = vec![0; 16 * 1024];
    for (id, at, bytes, kind) in [
        (1, DIRECTORY, directory, 1),
        (2, READ, read, if case == 3 { 1 } else { 196 }),
        (3, WRITE, write, 196),
        (4, DESCRIPTIONS, descriptions, 196),
    ] {
        table[id * 512..(id + 1) * 512].copy_from_slice(&node(&bytes, at, kind, order));
        blocks.insert(BASE + at, bytes);
    }
    if case == 4 {
        for (at, bytes) in install_graph_catalogs(&mut table, order) {
            blocks.insert(BASE + at, bytes);
        }
    }
    if case == 5 {
        let mut sparse = node(&[0; 512], DATA_OFFSET, 19, order);
        sparse[64..192].fill(0);
        sparse[112..120].copy_from_slice(&order.encode(19_u64 << 48));
        sparse[144..152].copy_from_slice(&order.encode(10));
        table[5 * 512..6 * 512].copy_from_slice(&sparse);
    }
    let mut data = vec![0; 1024];
    data[..512].copy_from_slice(&node(&table, TABLE, 10, order));
    data[704..712].copy_from_slice(&order.encode(1));
    blocks.insert(BASE + TABLE, table);
    let bp = BlockPointer::parse(&pointer(&data, DATA_OFFSET, 11, 30, order), order).unwrap();
    let reads = Arc::new(Mutex::new(Vec::new()));
    let leaf = Leaf::from_device(
        &Cx::for_testing(),
        Box::new(Memory {
            blocks,
            reads: Arc::clone(&reads),
            failure,
        }),
        BASE,
        LENGTH,
    )
    .unwrap();
    let root = RootBlock {
        uberblock: Uberblock {
            order,
            version: 5000,
            txg: 40,
            guid_sum: 3,
            timestamp: 1,
            root: bp,
        },
        data,
        physical_offset: DATA_OFFSET,
        copy_index: 0,
        member_guid: 2,
        raidz: None,
        config: VdevConfig {
            pool_guid: 1,
            top_guid: 2,
            version: 5000,
            txg: 40,
            ashift: 9,
            id: 0,
            allocated_bytes: LENGTH - DATA_OFFSET - 2 * 256 * 1024,
            read_features: if case == 4 {
                vec![
                    "org.illumos:lz4_compress".into(),
                    "com.delphix:embedded_data".into(),
                ]
            } else if case == 5 {
                vec!["com.delphix:hole_birth".into()]
            } else {
                Vec::new()
            },
            raidz_members: None,
        },
    };
    (leaf.into(), root, reads)
}

#[test]
fn admitted_hole_birth_mos_reads_and_seeks_sparse_data_without_payload_io() {
    for order in [Endian::Little, Endian::Big] {
        let cx = Cx::for_testing();
        let (pool, root, reads) = fixture(order, 1, 5, None);
        let mut view = Objects::from_root(&cx, pool, root).unwrap();
        let before = reads.lock().unwrap().len();
        assert_eq!(view.read(&cx, 5, 37, 111).unwrap(), [0; 111]);
        let object = view.load(&cx, 5).unwrap();
        assert_eq!(
            view.seek_data_hole(&cx, &object, 512, 37, false).unwrap(),
            37
        );
        assert!(matches!(view.seek_data_hole(&cx, &object, 512, 37, true),
            Err(FfsError::Io(error)) if error.raw_os_error() == Some(libc::ENXIO)));
        assert_eq!(reads.lock().unwrap().len(), before);
    }
}

#[test]
fn shared_graph_catalogs_pass_the_real_constructor_with_both_label_features() {
    for order in [Endian::Little, Endian::Big] {
        let cx = Cx::for_testing();
        let (pool, root, reads) = fixture(order, 0, 4, None);
        let mut view = Objects::from_root(&cx, pool, root).unwrap();
        for id in 29..=31 {
            assert_eq!(view.object(&cx, id).unwrap().object_type(), 196);
        }
        let log = reads.lock().unwrap();
        assert!(log.contains(&(BASE + DATA_OFFSET + 0x14400)));
        assert!(log.contains(&(BASE + DATA_OFFSET + 0x14600)));
        assert!(!log.contains(&(BASE + DATA_OFFSET + 0x14800)));
    }
}

#[test]
fn checked_mos_open_rejects_unknown_active_read_features_before_returning_a_view() {
    for order in [Endian::Little, Endian::Big] {
        let (pool, root, reads) = fixture(order, 0, 0, None);
        assert!(Objects::from_root(&Cx::for_testing(), pool, root).is_ok());
        let log = reads.lock().unwrap();
        assert!(log.contains(&(BASE + READ)) && log.contains(&(BASE + WRITE)));
        assert!(!log.contains(&(BASE + DESCRIPTIONS))); // Not compatibility authority.
        drop(log);
        for count in [1, u64::MAX] {
            let (pool, root, _) = fixture(order, count, 0, None);
            assert!(matches!(
                Objects::from_root(&Cx::for_testing(), pool, root),
                Err(FfsError::UnsupportedFeature(_))
            ));
        }
    }
}

#[test]
fn missing_aliased_or_mistyped_feature_objects_fail_the_shared_open_seam() {
    for order in [Endian::Little, Endian::Big] {
        for case in 1..=3 {
            let (pool, root, _) = fixture(order, 0, case, None);
            assert!(Objects::from_root(&Cx::for_testing(), pool, root).is_err());
        }
    }
}

#[test]
fn failed_or_cancelled_catalog_io_never_returns_an_admitted_view() {
    for at in [TABLE, DIRECTORY, READ, WRITE] {
        for cancel in [false, true] {
            let (pool, root, reads) = fixture(Endian::Little, 0, 0, Some((at, cancel)));
            let result = Objects::from_root(&Cx::for_testing(), pool, root);
            if cancel {
                assert!(matches!(result, Err(FfsError::Cancelled)));
            } else {
                assert!(result.is_err());
            }
            assert_eq!(reads.lock().unwrap().last(), Some(&(BASE + at)));
        }
    }
}

#[test]
fn numbered_pool_versions_do_not_invent_feature_catalog_reads() {
    let (pool, mut root, reads) = fixture(Endian::Big, 1, 1, Some((TABLE, false)));
    root.config.version = 28;
    root.uberblock.version = 28;
    assert!(Objects::from_root(&Cx::for_testing(), pool, root).is_ok());
    assert!(reads.lock().unwrap().is_empty());
}
