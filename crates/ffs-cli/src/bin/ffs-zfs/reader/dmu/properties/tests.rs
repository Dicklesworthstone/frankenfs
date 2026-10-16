//! Constructed checked-MOS graphs and policy adversaries, not native-pool proof.
use super::*;
use crate::reader::{ByteOffset, Leaf, VdevConfig};
use ffs_block::ByteDevice;
use ffs_ondisk::zfs::{DATA_OFFSET, Endian, checksum};
use ffs_ondisk::zfs_dmu::Dnode;
use std::sync::{Arc, Mutex};

fn number(name: &str, value: u64) -> Entry {
    Entry { name: name.as_bytes().to_vec(), values: vec![value], integer_bytes: 8, collision: 0 }
}
fn text(name: &str, value: &[u8]) -> Entry {
    Entry { name: name.as_bytes().to_vec(), values: value.iter().map(|b| u64::from(*b))
        .chain([0]).collect(), integer_bytes: 1, collision: 0 }
}
fn catalog(rows: Vec<Entry>) -> Catalog {
    rows.into_iter().map(|row| (row.name.clone(), row)).collect()
}
fn names(values: &[&str]) -> Vec<String> { values.iter().map(|s| (*s).into()).collect() }

#[test]
fn local_received_and_explicit_inherit_precedence_is_native() {
    let spec = Spec::named("readonly").unwrap();
    for bits in 0..8 {
        let mut rows = Vec::new();
        if bits & 1 != 0 { rows.push(number("readonly", 0)); }
        if bits & 2 != 0 { rows.push(number("readonly$recvd", 1)); }
        if bits & 4 != 0 { rows.push(number("readonly$inherit", 0)); }
        let map = catalog(rows);
        let expected = if bits & 1 != 0 {
            Some((PropertyValue::Number(0), PropertySource::Local))
        } else if bits & 6 == 2 {
            Some((PropertyValue::Number(1), PropertySource::Received))
        } else { None };
        for snapshot in [false, true] {
            assert_eq!(local_value(&map, "readonly", &spec, snapshot).unwrap(), expected);
        }
        assert_eq!(received(&map, "readonly", &spec).unwrap(),
            (bits & 2 != 0).then_some(PropertyValue::Number(1)));
    }
}

#[test]
fn recognized_iuv_precedes_local_but_unknown_iuv_and_snapshot_iuv_do_not() {
    let spec = Spec::named("canmount").unwrap();
    for index in [0, 1, 2, 3, u64::MAX] {
        let map = catalog(vec![number("canmount", 1), number("canmount$iuv", index)]);
        let value = if index <= 2 { index } else { 1 };
        assert_eq!(local_value(&map, "canmount", &spec, false).unwrap(),
            Some((PropertyValue::Number(value), PropertySource::Local)));
        assert_eq!(local_value(&map, "canmount", &spec, true).unwrap(),
            Some((PropertyValue::Number(1), PropertySource::Local)));
    }
    let mut row = number("canmount$iuv", 1);
    row.integer_bytes = 4;
    assert!(local_value(&catalog(vec![row]), "canmount", &spec, false).is_err());
    let spec = Spec::named("recordsize").unwrap();
    let map = catalog(vec![number("recordsize$iuv", 4096), number("recordsize", 8192)]);
    assert_eq!(local_value(&map, "recordsize", &spec, false).unwrap().unwrap().0,
        PropertyValue::Number(8192));
    let spec = Spec::named("compression").unwrap();
    for level in 0..=255 {
        let encoded = 16 | (level << 7);
        assert_eq!(spec.known_index(&PropertyValue::Number(encoded)),
            matches!(level, 0..=19 | 103..=123));
    }
}

#[test]
fn string_values_preserve_native_bytes_and_refuse_invalid_encodings() {
    let spec = Spec::named("example.org:owner").unwrap();
    for bytes in [b"".as_slice(), b"owner", &[0xff, 0xfe]] {
        assert_eq!(spec.decode(&text("example.org:owner", bytes)).unwrap(),
            PropertyValue::Text(bytes.to_vec()));
    }
    assert!(spec.decode(&text("p:x", &vec![b'a'; MAX_VALUE_BYTES - 1])).is_ok());
    assert!(spec.decode(&text("p:x", &vec![b'a'; MAX_VALUE_BYTES])).is_err());
    for values in [vec![], vec![b'a' as u64], vec![256, 0], vec![65, 0, 66, 0]] {
        let mut row = text("p:x", b"x");
        row.values = values;
        assert!(spec.decode(&row).is_err());
    }
    assert!(spec.decode(&number("p:x", 0)).is_err());
    let numeric = Spec::named("copies").unwrap();
    assert!(numeric.decode(&text("copies", b"1")).is_err());
    let mut row = number("copies", 1);
    row.values.push(2);
    assert!(numeric.decode(&row).is_err());
}

const BASE: u64 = 1024;
const LENGTH: u64 = 8 * 1024 * 1024;
const TABLE: u64 = DATA_OFFSET + 0x10000;
const OS: u64 = DATA_OFFSET + 0x20000;
fn address(id: u64) -> u64 { DATA_OFFSET + 0x14000 + id * 512 }
type Reads = Arc<Mutex<Vec<u64>>>;

struct Memory { blocks: BTreeMap<u64, Vec<u8>>, reads: Reads, failure: Option<(u64, bool)> }
impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 { BASE + LENGTH }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, out: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.reads.lock().unwrap().push(at.0);
        if let Some((offset, cancel)) = self.failure && at.0 == BASE + offset {
            return Err(if cancel { FfsError::Cancelled } else { corrupt("injected property read failure") });
        }
        let bytes = self.blocks.get(&at.0).filter(|b| b.len() == out.len())
            .ok_or_else(|| corrupt("unregistered property fixture read"))?;
        out.copy_from_slice(bytes);
        Ok(())
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> { panic!("property write") }
    fn sync(&self, _: &Cx) -> Result<()> { panic!("property flush") }
}
fn pointer(data: &[u8], at: u64, kind: u8, birth: u64, order: Endian) -> Vec<u8> {
    let sectors = data.len() as u64 / 512;
    let mut words = [0_u64; 16];
    words[0] = sectors;
    words[1] = (at - DATA_OFFSET) / 512;
    words[6] = (sectors - 1) | ((sectors - 1) << 16) | (2 << 32) | (7 << 40)
        | (u64::from(kind) << 48) | (u64::from(order == Endian::Little) << 63);
    words[10] = birth;
    words[12..].copy_from_slice(&checksum(data, 7, order).unwrap());
    words.into_iter().flat_map(|w| order.encode(w)).collect()
}
fn node(kind: u8, size: usize, bonus_kind: u8, bonus: &[u8], order: Endian) -> Vec<u8> {
    let mut raw = vec![0; 512];
    raw[0] = kind;
    raw[1] = 12;
    raw[2] = 1;
    raw[3] = 1;
    raw[4] = bonus_kind;
    raw[7] = 1;
    for (at, value) in [(8, (size / 512) as u16), (10, bonus.len() as u16)] {
        raw[at..at + 2].copy_from_slice(&match order {
            Endian::Little => value.to_le_bytes(), Endian::Big => value.to_be_bytes(),
        });
    }
    raw[192..192 + bonus.len()].copy_from_slice(bonus);
    raw
}
fn micro(rows: &[(&str, u64)], order: Endian) -> Vec<u8> {
    assert!(rows.len() <= 7);
    let mut raw = vec![0; 512];
    raw[..8].copy_from_slice(&order.encode((1 << 63) + 3));
    for (index, (name, value)) in rows.iter().enumerate() {
        let at = 64 + index * 64;
        raw[at..at + 8].copy_from_slice(&order.encode(*value));
        raw[at + 14..at + 14 + name.len()].copy_from_slice(name.as_bytes());
    }
    raw
}

// Complete MOS -> two DSL directories -> head/snapshot roots and property ZAPs.
// The private Objects constructor isolates this work from label/feature admission.
fn fixture(order: Endian, case: u8, failure: Option<(u64, bool)>) -> (Objects, Reads) {
    let mut blocks = BTreeMap::new();
    let mut table = vec![0; 16 * 1024];
    let parent_rows = [("readonly", 1), ("exec", 0), ("canmount", 0)];
    let child_rows = [("readonly$recvd", 0), ("readonly$inherit", 0), ("atime", 0)];
    let snap_rows = [("exec$recvd", 1), ("exec$inherit", 0), ("context$inherit", 0)];
    for (id, kind, rows) in [
        (1, 1, vec![("root_dataset", 2)]), (4, 13, vec![("data", 5)]),
        (7, 15, parent_rows.to_vec()), (8, 196, child_rows.to_vec()),
        (9, 14, vec![("before", 10)]), (11, 15, snap_rows.to_vec()),
    ] {
        let data = micro(&rows, order);
        let mut dn = node(if case == 3 && id == 8 { 20 } else { kind }, 512, 0, &[], order);
        dn[64..192].copy_from_slice(&pointer(&data, address(id), kind, 70, order));
        table[id as usize * 512..(id as usize + 1) * 512].copy_from_slice(&dn);
        blocks.insert(BASE + address(id), data);
    }
    for (id, head, parent, children, props) in [(2, 3, 0, 4, 7), (5, 6, 2, 0, 8)] {
        let mut bonus = vec![0; 256];
        for (at, value) in [(8, head), (16, parent), (24, 999), (32, children), (80, props)] {
            bonus[at..at + 8].copy_from_slice(&order.encode(value));
        }
        if id == 5 {
            // The origin is deliberately irrelevant to property inheritance.
            bonus[24..32].fill(0);
            if case == 1 { bonus[80..88].fill(0); }
            if case == 2 { bonus[80..88].copy_from_slice(&order.encode(7)); }
            if case == 4 { bonus[16..24].copy_from_slice(&order.encode(5)); }
        }
        table[id * 512..(id + 1) * 512].copy_from_slice(&node(12, 512, 12, &bonus, order));
    }
    let mut os = vec![0; 1024];
    os[..512].copy_from_slice(&node(10, 16384, 0, &[], order));
    os[704..712].copy_from_slice(&order.encode(if case == 5 { 3 } else { 2 }));
    blocks.insert(BASE + OS, os.clone());
    for (id, directory, previous, previous_txg, next, map, children, creation, birth, props) in [
        (3, 2, 0, 0, 0, 0, 0, 5, 40, 0),
        (6, 5, 10, 30, 0, 9, 0, 5, 40, 0),
        (10, 5, 0, 0, 6, 0, 1, 30, 20, 11),
    ] {
        let mut bonus = vec![0; 320];
        for (at, value) in [(0, directory), (8, previous), (16, previous_txg),
            (24, next), (32, map), (40, children), (56, creation), (112, 1000 + id as u64),
            (120, 4), (264, props)] {
            bonus[at..at + 8].copy_from_slice(&order.encode(value));
        }
        bonus[128..256].copy_from_slice(&pointer(&os, OS, 11, birth, order));
        table[id * 512..(id + 1) * 512].copy_from_slice(&node(16, 512, 16, &bonus, order));
    }
    let mut meta = node(10, 16384, 0, &[], order);
    meta[64..192].copy_from_slice(&pointer(&table, TABLE, 10, 80, order));
    blocks.insert(BASE + TABLE, table);
    if case == 6 {
        blocks.get_mut(&(BASE + address(7))).unwrap()[80] ^= 1;
    }
    let reads = Arc::new(Mutex::new(Vec::new()));
    let leaf = Leaf::from_device(&Cx::for_testing(), Box::new(Memory {
        blocks, reads: Arc::clone(&reads), failure,
    }), BASE, LENGTH).unwrap();
    (Objects {
        pool: leaf.into(), config: VdevConfig {
            pool_guid: 123, top_guid: 999, version: 5000, txg: 90, ashift: 9, id: 0,
            allocated_bytes: LENGTH - DATA_OFFSET - 512 * 1024,
            read_features: Vec::new(), raidz_members: None,
        }, txg: 100, root_birth: 90, meta: Dnode::parse(&meta, order).unwrap(),
        cache: std::collections::VecDeque::new(), cached_bytes: 0,
    }, reads)
}
fn data() -> Vec<Vec<u8>> { vec![b"data".to_vec()] }

#[test]
fn native_mos_inheritance_defaults_and_received_provenance_agree_in_both_orders() {
    for order in [Endian::Little, Endian::Big] {
        let (mut view, reads) = fixture(order, 0, None);
        let report = view.properties(&Cx::for_testing(), &data(), None,
            &names(&["readonly", "atime", "canmount", "p:missing"])).unwrap();
        assert_eq!((report.pool_guid, report.pool_txg, report.dataset_guid), (123, 100, 1006));
        let inherited = &report.values[0];
        assert_eq!(inherited.value, Some(PropertyValue::Number(1)));
        assert_eq!(inherited.source, PropertySource::Inherited);
        assert_eq!(inherited.stored_source, Some(PropertySource::Local));
        assert_eq!(inherited.setpoint, Some(Vec::new()));
        assert_eq!(inherited.received, Some(PropertyValue::Number(0)));
        assert_eq!(report.values[1].source, PropertySource::Local);
        assert_eq!(report.values[1].value, Some(PropertyValue::Number(0)));
        assert_eq!(report.values[2].source, PropertySource::Default);
        assert_eq!(report.values[2].value, Some(PropertyValue::Number(1)));
        assert_eq!(report.values[3].source, PropertySource::Unset);
        assert!(report.values[3].value.is_none());
        assert!(reads.lock().unwrap().iter().all(|at| *at >= BASE && *at < BASE + LENGTH));
    }
}

#[test]
fn snapshot_properties_use_current_mos_state_but_never_change_data_root_selection() {
    for order in [Endian::Little, Endian::Big] {
        let (mut view, _) = fixture(order, 0, None);
        let report = view.properties(&Cx::for_testing(), &data(), Some(b"before"),
            &names(&["exec", "fscontext"])).unwrap();
        // Property ZAPs have birth 70, later than the snapshot's creation at 30.
        assert_eq!(report.pool_txg, 100);
        assert_eq!(report.snapshot_creation_txg, Some(30));
        assert_eq!(report.dataset_guid, 1010);
        assert_eq!(report.values[0].value, Some(PropertyValue::Number(0)));
        assert_eq!(report.values[0].source, PropertySource::Inherited);
        assert_eq!(report.values[0].received, Some(PropertyValue::Number(1)));
        assert_eq!(report.values[0].setpoint, Some(Vec::new()));
        assert_eq!(report.values[1].value, Some(PropertyValue::Text(b"none".to_vec())));
        assert!(view.properties(&Cx::for_testing(), &data(), Some(b"BEFORE"),
            &names(&["exec"])).is_err());
        assert!(view.properties(&Cx::for_testing(), &data(), Some(b"before"),
            &names(&["readonly"])).is_err());
        assert_eq!(view.txg, 100);
    }
}

#[test]
fn noninheritable_snapshot_properties_do_not_obey_an_inherit_marker() {
    let spec = Spec::named("context").unwrap();
    let map = catalog(vec![text("context$recvd", b"received"), number("context$inherit", 0)]);
    assert_eq!(local_value(&map, "context", &spec, true).unwrap(),
        Some((PropertyValue::Text(b"received".to_vec()), PropertySource::Received)));
    assert!(local_value(&map, "context", &spec, false).unwrap().is_none());
}

#[test]
fn local_and_noninheritable_queries_do_not_read_unneeded_parent_catalogs() {
    for name in ["atime", "canmount"] {
        let (mut view, reads) = fixture(Endian::Little, 0, Some((address(7), true)));
        assert!(view.properties(&Cx::for_testing(), &data(), None, &names(&[name])).is_ok());
        assert!(!reads.lock().unwrap().contains(&(BASE + address(7))));
    }
    let (mut view, reads) = fixture(Endian::Big, 0, Some((address(7), true)));
    assert!(matches!(view.properties(&Cx::for_testing(), &data(), None,
        &names(&["atime", "readonly"])), Err(FfsError::Cancelled)));
    assert_eq!(reads.lock().unwrap().last(), Some(&(BASE + address(7))));
}

#[test]
fn bad_catalog_identity_parent_or_checksum_fails_the_batch() {
    for case in [1, 2, 3, 4, 6] {
        let (mut view, _) = fixture(Endian::Little, case, None);
        assert!(view.properties(&Cx::for_testing(), &data(), None, &names(&["readonly"])).is_err());
    }
    for at in [TABLE, address(1), address(8), address(7)] {
        for cancel in [false, true] {
            let (mut view, _) = fixture(Endian::Big, 0, Some((at, cancel)));
            let result = view.properties(&Cx::for_testing(), &data(), None, &names(&["readonly"]));
            if cancel { assert!(matches!(result, Err(FfsError::Cancelled))); }
            else { assert!(result.is_err()); }
        }
    }
}

#[test]
fn volume_and_name_admission_happen_without_invented_native_properties() {
    let (mut view, reads) = fixture(Endian::Little, 5, None);
    assert!(view.properties(&Cx::for_testing(), &data(), None, &names(&["readonly"])).is_ok());
    assert!(view.properties(&Cx::for_testing(), &data(), None, &names(&["atime"])).is_err());
    reads.lock().unwrap().clear();
    for query in [names(&[]), names(&["used"]), names(&["mountpoint"]), names(&["P:x"]),
        names(&["p:x$recvd"]), names(&["atime", "atime"]), vec!["p:x".into(); MAX_QUERIES + 1]] {
        assert!(view.properties(&Cx::for_testing(), &data(), None, &query).is_err());
    }
    assert!(reads.lock().unwrap().is_empty());
}
