//! Constructed native-label/MOS graphs, not OpenZFS-created pool evidence.
use super::*;
use crate::reader::Pool;
use crate::reader::tests::mirror::{
    Fault, MIRROR_GUID, install_labels, native_config, open_bytes, repack,
};
use crate::reader::tests::raidz::fixture::StripedImage;
use ffs_ondisk::zfs::{DATA_OFFSET, Endian, LABEL_BYTES, checksum};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const BASE: usize = 1024;
const LENGTH: usize = 8 * 1024 * 1024;
const ASIZE: u64 = LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES;
const TABLE: u64 = DATA_OFFSET + 0x10000;
const DIRECTORY: u64 = DATA_OFFSET + 0x14000;
const READ_FEATURES: u64 = DIRECTORY + 512;
const WRITE_FEATURES: u64 = READ_FEATURES + 512;
const DESCRIPTIONS: u64 = WRITE_FEATURES + 512;
const CONFIG: u64 = DATA_OFFSET + 0x18000;
const ARRAY: u64 = DATA_OFFSET + 0x20000;
const MAP_A: u64 = DATA_OFFSET + 0x21000;
const MAP_B: u64 = DATA_OFFSET + 0x22000;
const ROOT: u64 = DATA_OFFSET + 0x28000;
const SLAB: u64 = 1 << 20;
type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

fn nv(fields: &[(&str, Value)]) -> NvList {
    NvList {
        fields: fields
            .iter()
            .map(|(key, value)| ((*key).into(), value.clone()))
            .collect(),
    }
}
fn text(value: &str) -> Value {
    Value::String(value.into())
}
fn u(value: u64) -> Value {
    Value::Unsigned(value)
}
fn w16(raw: &mut [u8], at: usize, value: u16, order: Endian) {
    raw[at..at + 2].copy_from_slice(&match order {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    });
}
fn w64(raw: &mut [u8], at: usize, value: u64, order: Endian) {
    raw[at..at + 8].copy_from_slice(&order.encode(value));
}
fn pointer(
    data: &[u8],
    at: u64,
    kind: u8,
    birth: u64,
    container: Endian,
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
        | (u64::from(payload == Endian::Little) << 63);
    words[10] = birth;
    words[12..].copy_from_slice(&checksum(data, 7, payload).unwrap());
    words
        .into_iter()
        .flat_map(|word| container.encode(word))
        .collect()
}
fn node(
    kind: u8,
    size: usize,
    pointers: &[Vec<u8>],
    bonus_kind: u8,
    bonus: &[u8],
    order: Endian,
) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = 1;
    raw[3] = pointers.len() as u8;
    raw[4] = bonus_kind;
    raw[7] = 1;
    w16(&mut raw, 8, (size / 512) as u16, order);
    w16(&mut raw, 10, bonus.len() as u16, order);
    w64(&mut raw, 16, pointers.len() as u64 - 1, order);
    for (index, bp) in pointers.iter().enumerate() {
        raw[64 + index * 128..192 + index * 128].copy_from_slice(bp);
    }
    let start = 64 + pointers.len() * 128;
    raw[start..start + bonus.len()].copy_from_slice(bonus);
    raw
}
fn micro(entries: &[(&[u8], u64)], order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 512];
    w64(&mut raw, 0, (1 << 63) + 3, order);
    assert!(entries.len() <= 7);
    for (index, (name, value)) in entries.iter().enumerate() {
        let at = 64 + index * 64;
        w64(&mut raw, at, *value, order);
        raw[at + 14..at + 14 + name.len()].copy_from_slice(name);
    }
    raw
}

struct Image {
    bytes: Vec<u8>,
    root: Vec<u8>,
    label: NvList,
    uberblock: Vec<u8>,
    width: usize,
}

impl Image {
    fn new(order: Endian, case: u8) -> Self {
        Self::group(order, case, 1, 0)
    }

    fn group(order: Endian, case: u8, width: usize, parity: usize) -> Self {
        let other = if order == Endian::Little {
            Endian::Big
        } else {
            Endian::Little
        };
        let guid = if width == 1 { 1001 } else { MIRROR_GUID };
        let asize = if parity == 0 {
            ASIZE
        } else {
            ASIZE * width as u64
        };
        let mut top = nv(&[
            (
                "type",
                text(if width == 1 {
                    "file"
                } else if parity == 0 {
                    "mirror"
                } else {
                    "raidz"
                }),
            ),
            ("id", u(0)),
            ("guid", u(guid)),
            ("ashift", u(9)),
            ("asize", u(asize)),
            ("is_log", u(0)),
            ("metaslab_shift", u(20)),
            ("metaslab_array", u(6)),
        ]);
        if width > 1 {
            let children = (0..width)
                .map(|id| {
                    nv(&[
                        ("type", text("file")),
                        ("id", u(id as u64)),
                        ("guid", u(1001 + id as u64)),
                    ])
                })
                .collect();
            top.fields.insert("children".into(), Value::Lists(children));
            if parity != 0 {
                top.fields.insert("nparity".into(), u(parity as u64));
            }
        }
        let label = nv(&[
            ("version", u(5000)),
            ("state", u(1)),
            ("txg", u(90)),
            ("pool_guid", u(123)),
            ("guid", u(1001)),
            ("top_guid", u(guid)),
            ("vdev_children", u(1)),
            ("name", text("allocation-fixture")),
            ("vdev_tree", Value::List(top.clone())),
            (
                "features_for_read",
                Value::List(nv(&[
                    ("org.illumos:lz4_compress", Value::Boolean(true)),
                    ("com.delphix:embedded_data", Value::Boolean(true)),
                ])),
            ),
        ]);
        match case {
            11 => {
                top.fields.insert("guid".into(), u(999));
            }
            12 => {
                top.fields.insert("metaslab_shift".into(), u(8));
            }
            13 => {
                top.fields.insert("asize".into(), u(asize + 512));
            }
            21 => {
                top.fields.insert("metaslab_array".into(), u(5));
            }
            _ => {}
        }
        let config = nv(&[
            ("pool_guid", u(123)),
            ("version", u(5000)),
            ("txg", u(90)),
            (
                "vdev_tree",
                Value::List(nv(&[
                    ("type", text("root")),
                    ("id", u(0)),
                    ("guid", u(123)),
                    ("children", Value::Lists(vec![top])),
                ])),
            ),
        ]);
        let mut packed = repack(&config);
        let packed_length = if case == 20 { 0 } else { packed.len() as u64 };
        assert!(packed.len() <= 4096);
        packed.resize(4096, 0);
        let directory = micro(
            &[
                (b"config", 5),
                (b"features_for_read", 2),
                (b"features_for_write", 3),
                (b"feature_descriptions", 4),
            ],
            other,
        );
        let read = micro(
            &[
                (b"org.illumos:lz4_compress", 1),
                (b"com.delphix:embedded_data", 1),
            ],
            other,
        );
        let write = micro(
            &[
                (b"com.delphix:spacemap_v2", u64::from(case != 16)),
                (b"com.delphix:log_spacemap", u64::from(case == 14)),
                (b"com.delphix:zpool_checkpoint", u64::from(case == 15)),
            ],
            other,
        );
        let descriptions = micro(&[], order);
        let mut array = vec![0; 512];
        w64(&mut array, 0, 7, other);
        w64(&mut array, 8, if case == 9 { 7 } else { 8 }, other);
        let mut first = vec![0; 512];
        for at in (0..512).step_by(8) {
            w64(&mut first, at, 2 << 62, other);
        }
        w64(&mut first, 0, 7, other); // allocate [0, 8) units
        w64(&mut first, 8, (2 << 16) | (1 << 15) | 1, other); // free [2, 4)
        if case == 4 {
            w64(&mut first, 0, 1 << 15, other);
        }
        if case == 5 {
            w64(&mut first, 8, 0, other);
        }
        let mut second = vec![0; 512];
        w64(
            &mut second,
            0,
            (3 << 62) | (1 << 24) | u64::from(case == 6),
            order,
        );
        w64(&mut second, 8, 8, order); // allocate [8, 10)
        // Slack is deliberately nonsensical: only smp_length is interpreted.
        second[16..].fill(0xff);
        let mut last = vec![0xff; 512];
        w64(&mut last, 0, (1 << 16) | 2, other); // allocate [1, 4)
        let mut header_a = vec![0; 24];
        w64(&mut header_a, 0, u64::MAX, order); // obsolete smp_object
        w64(
            &mut header_a,
            8,
            match case {
                2 => 520,
                7 => 1536,
                _ => 528,
            },
            order,
        );
        w64(
            &mut header_a,
            16,
            match case {
                1 => 4608,
                8 => u64::MAX,
                _ => 4096,
            },
            order,
        );
        let mut header_b = vec![0; 320];
        w64(&mut header_b, 8, 8, order);
        w64(&mut header_b, 16, 1536, order);
        w64(&mut header_b, 64, 123, order); // histogram is not allocation authority
        let mut table = vec![0; 16 * 1024];
        let mut blocks = BTreeMap::new();
        for (id, at, bytes, kind, bonus_kind, bonus, payload) in [
            (1, DIRECTORY, directory, 1, 0, Vec::new(), other),
            (2, READ_FEATURES, read, 196, 0, Vec::new(), other),
            (3, WRITE_FEATURES, write, 196, 0, Vec::new(), other),
            (4, DESCRIPTIONS, descriptions, 196, 0, Vec::new(), order),
            (
                5,
                CONFIG,
                packed,
                3,
                4,
                order.encode(packed_length).to_vec(),
                order,
            ),
            (
                6,
                ARRAY,
                array,
                if case == 10 { 1 } else { 2 },
                0,
                Vec::new(),
                other,
            ),
            (
                8,
                MAP_B,
                last,
                8,
                if case == 19 { 6 } else { 7 },
                header_b,
                other,
            ),
        ] {
            let bp = pointer(&bytes, at, kind, 70, order, payload);
            let dn = node(kind, bytes.len(), &[bp], bonus_kind, &bonus, order);
            table[id * 512..(id + 1) * 512].copy_from_slice(&dn);
            blocks.insert(at, bytes);
        }
        let pointers = [
            pointer(
                &first,
                MAP_A,
                8,
                if case == 18 { 81 } else { 70 },
                order,
                other,
            ),
            if case == 3 {
                vec![0; 128]
            } else {
                pointer(&second, MAP_A + 512, 8, 70, order, order)
            },
        ];
        table[7 * 512..8 * 512].copy_from_slice(&node(8, 512, &pointers, 7, &header_a, order));
        blocks.insert(MAP_A, first);
        blocks.insert(MAP_A + 512, second);
        let meta = node(
            10,
            table.len(),
            &[pointer(&table, TABLE, 10, 80, order, order)],
            0,
            &[],
            order,
        );
        let mut root = vec![0; 1024];
        root[..512].copy_from_slice(&meta);
        w64(&mut root, 704, 1, order);
        blocks.insert(TABLE, table);
        blocks.insert(ROOT, root.clone());
        let mut bytes = vec![0; BASE + LENGTH + 512];
        bytes[..BASE].fill(0xa5);
        bytes[BASE + LENGTH..].fill(0x5a);
        for (at, block) in blocks {
            let start = BASE + at as usize;
            bytes[start..start + block.len()].copy_from_slice(&block);
        }
        let mut uberblock = vec![0; 1024];
        let guid_sum = 123
            + if width == 1 {
                1001
            } else {
                MIRROR_GUID + (0..width).map(|id| 1001 + id as u64).sum::<u64>()
            };
        for (at, value) in [
            (0, 0x00ba_b10c),
            (8, 5000),
            (16, 100),
            (24, guid_sum),
            (32, 1_700_000_000),
        ] {
            w64(&mut uberblock, at, value, order);
        }
        uberblock[40..168].copy_from_slice(&pointer(&root, ROOT, 11, 90, order, order));
        install_labels(
            &mut bytes,
            BASE,
            LENGTH as u64,
            order,
            &repack(&label),
            &uberblock,
        );
        Self {
            bytes,
            root,
            label,
            uberblock,
            width,
        }
    }

    fn open(self, fault: Fault, reads: Reads) -> Objects {
        assert_eq!(self.width, 1);
        let leaf = open_bytes(self.bytes, BASE, LENGTH as u64, reads, fault);
        leaf.objects(&Cx::for_testing(), 0, 2, 123).unwrap()
    }
}

fn has_read(reads: &Reads, offset: u64) -> bool {
    reads
        .lock()
        .unwrap()
        .iter()
        .any(|(at, _)| *at == BASE as u64 + offset)
}

#[test]
fn whole_mos_allocation_uses_per_block_endian_and_exact_stream_lengths() {
    for order in [Endian::Little, Endian::Big] {
        let reads: Reads = Arc::default();
        let view = Image::new(order, 0).open(Fault::None, Arc::clone(&reads));
        let report = view
            .allocation(&Cx::for_testing(), AllocationLimits::default())
            .unwrap();
        assert_eq!(
            (report.pool_guid, report.txg, report.mapped_bytes),
            (123, 100, 3 * SLAB)
        );
        assert_eq!(
            (
                report.allocated_bytes,
                report.free_bytes,
                report.records_examined
            ),
            (5632, 3 * SLAB - 5632, 66)
        );
        let top = &report.vdevs[0];
        assert_eq!(
            (top.asize, top.unmapped_tail_bytes, top.metaslabs.len()),
            (ASIZE, 512 * 1024, 3)
        );
        let first = &top.metaslabs[0];
        assert_eq!(
            (
                first.allocated_bytes,
                first.allocated_ranges,
                first.free_ranges,
                first.largest_free_range
            ),
            (4096, 2, 2, SLAB - 5120)
        );
        assert_eq!(top.metaslabs[1].allocated_bytes, 1536);
        assert_eq!(
            (top.metaslabs[2].object, top.metaslabs[2].free_bytes),
            (0, SLAB)
        );
        assert!(!has_read(&reads, MAP_B + 512));
        assert!(view.cache.iter().all(|(bp, _)| bp.object_type() != 8));
        assert!(
            reads.lock().unwrap().iter().all(
                |(at, size)| *at >= BASE as u64 && *at + *size as u64 <= (BASE + LENGTH) as u64
            )
        );
    }
}

#[test]
fn invalid_logs_counters_and_missing_blocks_fail_the_complete_report() {
    for order in [Endian::Little, Endian::Big] {
        for case in [1, 2, 3, 4, 5, 6, 7, 8, 16, 18, 19] {
            let view = Image::new(order, case).open(Fault::None, Arc::default());
            assert!(
                view.allocation(&Cx::for_testing(), AllocationLimits::default())
                    .is_err(),
                "case {case}"
            );
            assert!(view.cache.iter().all(|(bp, _)| bp.object_type() != 8));
        }
    }
}

#[test]
fn geometry_and_alias_conflicts_are_rejected_before_any_space_map_read() {
    for case in [9, 10, 11, 12, 13, 20, 21] {
        let reads: Reads = Arc::default();
        let view = Image::new(Endian::Little, case).open(Fault::None, Arc::clone(&reads));
        assert!(
            view.allocation(&Cx::for_testing(), AllocationLimits::default())
                .is_err(),
            "case {case}"
        );
        assert!(!has_read(&reads, MAP_A) && !has_read(&reads, MAP_B));
    }
}

#[test]
fn active_log_space_maps_and_checkpoints_never_become_base_map_free_totals() {
    for case in [14, 15] {
        let reads: Reads = Arc::default();
        let view = Image::new(Endian::Little, case).open(Fault::None, Arc::clone(&reads));
        assert!(matches!(
            view.allocation(&Cx::for_testing(), AllocationLimits::default()),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert!(!has_read(&reads, CONFIG));
        assert!(!has_read(&reads, ARRAY));
        assert!(!has_read(&reads, MAP_A));
    }
}

#[test]
fn later_io_failure_checksum_failure_and_cancellation_discard_private_reconstruction() {
    for offset in [CONFIG, ARRAY, MAP_A, MAP_A + 512, MAP_B] {
        for cancel in [false, true] {
            let reads: Reads = Arc::default();
            let fault = if cancel {
                Fault::Cancel(BASE as u64 + offset)
            } else {
                Fault::Io(BASE as u64 + offset)
            };
            let view = Image::new(Endian::Big, 0).open(fault, Arc::clone(&reads));
            let result = view.allocation(&Cx::for_testing(), AllocationLimits::default());
            if cancel {
                assert!(matches!(result, Err(FfsError::Cancelled)));
            } else {
                assert!(result.is_err());
            }
            assert_eq!(
                reads.lock().unwrap().last().unwrap().0,
                BASE as u64 + offset
            );
        }
        let mut image = Image::new(Endian::Little, 0);
        image.bytes[BASE + offset as usize] ^= 1;
        let view = image.open(Fault::None, Arc::default());
        assert!(
            view.allocation(&Cx::for_testing(), AllocationLimits::default())
                .is_err()
        );
    }
}

#[test]
fn caller_limits_bound_metadatas_reads_records_and_interval_splits() {
    let reads: Reads = Arc::default();
    let view = Image::new(Endian::Little, 0).open(Fault::None, Arc::clone(&reads));
    for limits in [
        AllocationLimits {
            metadata_bytes: 1,
            ..AllocationLimits::default()
        },
        AllocationLimits {
            metaslabs: 0,
            ..AllocationLimits::default()
        },
        AllocationLimits {
            records: 0,
            ..AllocationLimits::default()
        },
        AllocationLimits {
            ranges_per_metaslab: 0,
            ..AllocationLimits::default()
        },
    ] {
        reads.lock().unwrap().clear();
        assert!(view.allocation(&Cx::for_testing(), limits).is_err());
        assert!(reads.lock().unwrap().is_empty());
    }
    for limits in [
        AllocationLimits {
            metaslabs: 2,
            ..AllocationLimits::default()
        },
        AllocationLimits {
            records: 64,
            ..AllocationLimits::default()
        },
        AllocationLimits {
            ranges_per_metaslab: 1,
            ..AllocationLimits::default()
        },
    ] {
        assert!(view.allocation(&Cx::for_testing(), limits).is_err());
    }
    let result = view
        .allocation(&Cx::for_testing(), AllocationLimits::default())
        .unwrap();
    assert_eq!(result.allocated_bytes, 5632);
    assert!(result.charged_metadata_bytes > 0);
}

#[test]
fn mirror_allocation_uses_verified_alternatives_and_checks_member_identity() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let image = Image::group(order, 0, 2, 0);
        let guids = [1001, 1002];
        let reads: [Reads; 2] = std::array::from_fn(|_| Arc::default());
        let members: Vec<_> = (0..2)
            .rev()
            .map(|index| {
                let mut bytes = image.bytes.clone();
                let config = native_config(guids[index], &guids, 9, ASIZE, 90);
                install_labels(
                    &mut bytes,
                    BASE,
                    LENGTH as u64,
                    order,
                    &config,
                    &image.uberblock,
                );
                if index == 1 {
                    bytes[BASE + MAP_A as usize + 512] ^= 1;
                }
                open_bytes(
                    bytes,
                    BASE,
                    LENGTH as u64,
                    Arc::clone(&reads[index]),
                    Fault::None,
                )
            })
            .collect();
        let pool = Pool::from_leaves(members).unwrap();
        let view = pool.objects(&cx, 0, 2, 123).unwrap();
        drop(pool);
        let report = view.allocation(&cx, AllocationLimits::default()).unwrap();
        assert_eq!(report.allocated_bytes, 5632);
        assert!(has_read(&reads[0], MAP_A + 512) && has_read(&reads[1], MAP_A + 512));
        let mut mos = nv(&[
            ("version", u(5000)),
            ("txg", u(90)),
            ("pool_guid", u(123)),
            (
                "vdev_tree",
                Value::List(nv(&[
                    ("type", text("root")),
                    ("id", u(0)),
                    ("guid", u(123)),
                    (
                        "children",
                        Value::Lists(vec![image.label.list("vdev_tree").unwrap().clone()]),
                    ),
                ])),
            ),
        ]);
        let Value::List(root) = mos.fields.get_mut("vdev_tree").unwrap() else {
            panic!("root");
        };
        let Value::Lists(tops) = root.fields.get_mut("children").unwrap() else {
            panic!("tops");
        };
        let Value::Lists(leaves) = tops[0].fields.get_mut("children").unwrap() else {
            panic!("leaves");
        };
        leaves[0].fields.insert("guid".into(), u(2222));
        assert!(view.allocation_topology(&cx, &mos).is_err());
    }
}

#[test]
fn raidz_allocation_retains_native_asize_domain_across_all_parities() {
    let cx = Cx::for_testing();
    for parity in 1..=3 {
        for order in [Endian::Little, Endian::Big] {
            let width = parity + 2;
            let source = Image::group(order, 0, width, parity);
            let mut stripes = StripedImage::graph_with_parity(
                &source.bytes,
                source.root,
                order,
                width,
                100,
                90,
                parity,
            );
            stripes.poison(MAP_A + 512, parity, 0);
            let pool = stripes.open(&vec![Fault::None; width], true);
            let view = pool.objects(&cx, 0, 2, 123).unwrap();
            let report = view.allocation(&cx, AllocationLimits::default()).unwrap();
            let expected = ASIZE * width as u64 / SLAB * SLAB;
            assert_eq!(report.mapped_bytes, expected);
            assert_eq!(report.allocated_bytes, 5632);
            assert_eq!(report.free_bytes + report.allocated_bytes, expected);
            assert_eq!(report.vdevs[0].asize, ASIZE * width as u64);
        }
    }
}
