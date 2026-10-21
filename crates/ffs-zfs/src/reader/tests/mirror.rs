//! Constructed native mirror graphs. These exercise admission and reads, not
//! OpenZFS import or a native mapping oracle.

use super::*;

pub(in crate::reader) const MIRROR_GUID: u64 = 777;

pub(in crate::reader) fn native_config(
    member: u64,
    members: &[u64],
    ashift: u64,
    asize: u64,
    txg: u64,
) -> Vec<u8> {
    let children: Vec<_> = members
        .iter()
        .enumerate()
        .flat_map(|(id, guid)| {
            list(&[
                pair("type", 9, &xstring("file")),
                uint("id", id as u64),
                uint("guid", *guid),
                // Ordinary mirror child labels have no ashift/asize fields.
                pair("path", 9, &xstring("/native/path/is/not/a/host/input")),
            ])
        })
        .collect();
    let mut array = pair("children", 20, &children);
    let elements = 8 + xstring("children").len() + 4;
    array[elements..elements + 4].copy_from_slice(&(members.len() as u32).to_be_bytes());
    let tree = list(&[
        pair("type", 9, &xstring("mirror")),
        uint("id", 0),
        uint("guid", MIRROR_GUID),
        uint("ashift", ashift),
        uint("asize", asize),
        uint("is_log", 0),
        array,
    ]);
    let mut bytes = vec![1, 1, 0, 0];
    bytes.extend_from_slice(&list(&[
        uint("version", 5000),
        uint("state", 1),
        uint("txg", txg),
        uint("pool_guid", 123),
        uint("guid", member),
        uint("top_guid", MIRROR_GUID),
        uint("vdev_children", 1),
        pair("name", 9, &xstring("mirror-fixture")),
        pair("vdev_tree", 19, &tree),
        pair(
            "features_for_read",
            19,
            &list(&[
                presence("org.illumos:lz4_compress"),
                presence("com.delphix:embedded_data"),
            ]),
        ),
    ]));
    bytes
}

pub(in crate::reader) fn install_labels(
    bytes: &mut [u8],
    base: usize,
    length: u64,
    order: Endian,
    config: &[u8],
    uberblock: &[u8],
) {
    for label in label_offsets(length).unwrap() {
        let offset = label + LABEL_CONFIG_OFFSET;
        let mut block = vec![0; LABEL_CONFIG_BYTES];
        block[..config.len()].copy_from_slice(config);
        stamp(&mut block, offset, order);
        let start = base + offset as usize;
        bytes[start..start + block.len()].copy_from_slice(&block);
        let offset = label + UBERBLOCK_RING_OFFSET + 2 * uberblock.len() as u64;
        let mut block = uberblock.to_vec();
        stamp(&mut block, offset, order);
        let start = base + offset as usize;
        bytes[start..start + block.len()].copy_from_slice(&block);
    }
}

#[derive(Clone, Copy)]
pub(in crate::reader) enum Fault {
    None,
    Io(u64),
    Cancel(u64),
}

struct Device {
    bytes: Vec<u8>,
    reads: Reads,
    fault: Fault,
}
impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, _: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push((offset.0, out.len()));
        match self.fault {
            Fault::Io(at) if at == offset.0 => {
                return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::EIO)));
            }
            Fault::Cancel(at) if at == offset.0 => return Err(FfsError::Cancelled),
            _ => {}
        }
        let start = usize::try_from(offset.0).map_err(|_| corrupt("test offset overflow"))?;
        let end = start
            .checked_add(out.len())
            .ok_or_else(|| corrupt("test span overflow"))?;
        out.copy_from_slice(
            self.bytes
                .get(start..end)
                .ok_or_else(|| corrupt("test read outside backing image"))?,
        );
        Ok(())
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("mirror extraction wrote a physical member")
    }
    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("mirror extraction flushed a physical member")
    }
}

pub(in crate::reader) fn open_bytes(
    bytes: Vec<u8>,
    base: usize,
    length: u64,
    reads: Reads,
    fault: Fault,
) -> Leaf {
    Leaf::from_device(
        &Cx::for_testing(),
        Box::new(Device {
            bytes,
            reads,
            fault,
        }),
        base as u64,
        length,
    )
    .unwrap()
}

struct Member {
    bytes: Vec<u8>,
    root: Vec<u8>,
    config: Vec<u8>,
    uberblock: Vec<u8>,
    order: Endian,
    length: u64,
    first: u64,
    second: u64,
}
impl Member {
    fn new(order: Endian, compressed: bool, ashift: u8, guid: u64, guids: &[u64]) -> Self {
        let image = Image::new(order, compressed);
        let physical_bytes = if compressed { 512 } else { 1024 };
        let physical =
            image.bytes[BASE + FIRST as usize..BASE + FIRST as usize + physical_bytes].to_vec();
        let sector = 1_u64 << ashift;
        let first = DATA_OFFSET + 2 * sector;
        let second = DATA_OFFSET + 4 * sector;
        let slot = uberblock_bytes(ashift).unwrap();
        let at = BASE + UBERBLOCK_RING_OFFSET as usize + 2 * 1024;
        let mut uberblock = image.bytes[at..at + 1024].to_vec();
        uberblock[984..].fill(0);
        uberblock.resize(slot, 0);
        let asize = (physical_bytes as u64).div_ceil(sector) * sector;
        let guid_sum = guids
            .iter()
            .fold(123_u64 + MIRROR_GUID, |sum, guid| sum.wrapping_add(*guid));
        for (at, value) in [
            (24, guid_sum),
            (40, asize / 512),
            (48, (first - DATA_OFFSET) / 512),
            (56, asize / 512),
            (64, (second - DATA_OFFSET) / 512),
        ] {
            uberblock[at..at + 8].copy_from_slice(&order.encode(value));
        }
        let mut result = Self {
            bytes: image.bytes,
            root: image.root,
            config: native_config(
                guid,
                guids,
                u64::from(ashift),
                LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES,
                42,
            ),
            uberblock,
            order,
            length: LENGTH as u64,
            first,
            second,
        };
        for offset in [first, second] {
            let at = BASE + offset as usize;
            result.bytes[at..at + physical.len()].copy_from_slice(&physical);
        }
        result.labels();
        result
    }
    fn labels(&mut self) {
        install_labels(
            &mut self.bytes,
            BASE,
            self.length,
            self.order,
            &self.config,
            &self.uberblock,
        );
    }
    fn open(self, reads: Reads, fault: Fault) -> Leaf {
        open_bytes(self.bytes, BASE, self.length, reads, fault)
    }
    fn poison(&mut self, offset: u64) {
        self.bytes[BASE + offset as usize] ^= 1;
    }
}

fn payload_reads(reads: &Reads, offsets: &[u64]) -> Vec<u64> {
    reads
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(at, _)| offsets.contains(at).then_some(*at))
        .collect()
}

// Fixture mutation only. The runtime decoder never serializes native labels.
pub(in crate::reader) fn repack(config: &NvList) -> Vec<u8> {
    fn nested(config: &NvList) -> Vec<u8> {
        let pairs: Vec<_> = config
            .fields
            .iter()
            .map(|(name, value)| match value {
                Value::Unsigned(value) => uint(name, *value),
                Value::String(value) => pair(name, 9, &xstring(value)),
                Value::Boolean(true) => presence(name),
                Value::List(value) => pair(name, 19, &nested(value)),
                Value::Lists(values) => {
                    let mut raw = pair(
                        name,
                        20,
                        &values.iter().flat_map(nested).collect::<Vec<_>>(),
                    );
                    let at = 8 + xstring(name).len() + 4;
                    raw[at..at + 4].copy_from_slice(&(values.len() as u32).to_be_bytes());
                    raw
                }
                _ => panic!("unsupported fixture mutation value"),
            })
            .collect();
        list(&pairs)
    }
    let mut result = vec![1, 1, 0, 0];
    result.extend_from_slice(&nested(config));
    result
}

#[test]
fn complete_mirrors_cover_widths_orders_compression_ashift_and_reversed_inputs() {
    let cx = Cx::for_testing();
    for (width, ashift) in [(2_u64, 9), (3, 12), (8, 16)] {
        let guids: Vec<_> = (0..width).map(|index| 1001 + index).collect();
        for order in [Endian::Little, Endian::Big] {
            for compressed in [false, true] {
                let expected = Member::new(order, compressed, ashift, guids[0], &guids).root;
                let reads: Reads = Arc::default();
                let leaves: Vec<_> = guids
                    .iter()
                    .rev()
                    .map(|guid| {
                        Member::new(order, compressed, ashift, *guid, &guids)
                            .open(Arc::clone(&reads), Fault::None)
                    })
                    .collect();
                let pool = Pool::from_leaves(leaves).unwrap();
                let root = pool.root(&cx, 0, 2, 123).unwrap();
                assert_eq!(root.data, expected);
                assert_eq!(root.member_guid, *guids.last().unwrap());
                assert_eq!(root.copy_index, 0);
                assert_eq!(root.physical_offset, DATA_OFFSET + 2 * (1_u64 << ashift));
                assert_eq!(root.uberblock.txg, 43);
                assert!(reads.lock().unwrap().iter().all(|(offset, count)| {
                    *offset >= BASE as u64 && *offset + *count as u64 <= (BASE + LENGTH) as u64
                }));
            }
        }
    }
}

#[test]
fn checksum_and_physical_io_failures_retry_members_before_the_next_dva() {
    let cx = Cx::for_testing();
    let guids = [1001, 1002, 1003];
    for all_first_copies_bad in [false, true] {
        let mut first = Member::new(Endian::Little, true, 12, guids[0], &guids);
        let second = Member::new(Endian::Little, true, 12, guids[1], &guids);
        let mut third = Member::new(Endian::Little, true, 12, guids[2], &guids);
        let at = first.first;
        let next = first.second;
        let expected = first.root.clone();
        first.poison(at);
        if all_first_copies_bad {
            third.poison(at);
        }
        let reads: [Reads; 3] = std::array::from_fn(|_| Arc::default());
        let pool = Pool::from_leaves(vec![
            first.open(Arc::clone(&reads[0]), Fault::None),
            second.open(Arc::clone(&reads[1]), Fault::Io(BASE as u64 + at)),
            third.open(Arc::clone(&reads[2]), Fault::None),
        ])
        .unwrap();
        let root = pool.root(&cx, 0, 2, 123).unwrap();
        assert_eq!(root.data, expected);
        assert_eq!(root.copy_index, usize::from(all_first_copies_bad));
        assert_eq!(
            root.member_guid,
            if all_first_copies_bad { 1001 } else { 1003 }
        );
        assert_eq!(
            root.physical_offset,
            if all_first_copies_bad { next } else { at }
        );
        let offsets = [BASE as u64 + at, BASE as u64 + next];
        assert_eq!(
            payload_reads(&reads[0], &offsets),
            if all_first_copies_bad {
                offsets.to_vec()
            } else {
                vec![offsets[0]]
            }
        );
        assert_eq!(payload_reads(&reads[1], &offsets), [offsets[0]]);
        assert_eq!(payload_reads(&reads[2], &offsets), [offsets[0]]);
    }
}

#[test]
fn all_copy_failure_and_cancellation_do_not_become_successful_roots() {
    let cx = Cx::for_testing();
    let guids = [1001, 1002];
    let mut a = Member::new(Endian::Big, false, 9, guids[0], &guids);
    let mut b = Member::new(Endian::Big, false, 9, guids[1], &guids);
    let offsets = [BASE as u64 + a.first, BASE as u64 + a.second];
    for member in [&mut a, &mut b] {
        member.poison(member.first);
        member.poison(member.second);
    }
    let logs: [Reads; 2] = std::array::from_fn(|_| Arc::default());
    let pool = Pool::from_leaves(vec![
        a.open(Arc::clone(&logs[0]), Fault::None),
        b.open(Arc::clone(&logs[1]), Fault::None),
    ])
    .unwrap();
    assert!(pool.root(&cx, 0, 2, 123).is_err());
    for reads in &logs {
        assert_eq!(payload_reads(reads, &offsets), offsets);
    }
    for first_is_io_error in [false, true] {
        let a = Member::new(Endian::Little, true, 9, guids[0], &guids);
        let b = Member::new(Endian::Little, true, 9, guids[1], &guids);
        let offsets = [BASE as u64 + a.first, BASE as u64 + a.second];
        let logs: [Reads; 2] = std::array::from_fn(|_| Arc::default());
        let first_fault = if first_is_io_error {
            Fault::Io(offsets[0])
        } else {
            Fault::Cancel(offsets[0])
        };
        let pool = Pool::from_leaves(vec![
            a.open(Arc::clone(&logs[0]), first_fault),
            b.open(Arc::clone(&logs[1]), Fault::Cancel(offsets[0])),
        ])
        .unwrap();
        assert!(matches!(
            pool.root(&cx, 0, 2, 123),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(payload_reads(&logs[0], &offsets), [offsets[0]]);
        assert_eq!(
            payload_reads(&logs[1], &offsets),
            if first_is_io_error {
                vec![offsets[0]]
            } else {
                Vec::new()
            }
        );
    }
}

#[test]
fn incomplete_duplicate_and_foreign_member_sets_fail_before_payload_reads() {
    let cx = Cx::for_testing();
    assert!(Pool::from_leaves(Vec::new()).is_err());
    let guids = [1001, 1002];
    for case in 0..5 {
        let first = Member::new(Endian::Little, false, 9, guids[0], &guids);
        let offsets = [BASE as u64 + first.first, BASE as u64 + first.second];
        let reads: Reads = Arc::default();
        let mut leaves = vec![first.open(Arc::clone(&reads), Fault::None)];
        match case {
            0 => {}
            1 => leaves.push(
                Member::new(Endian::Little, false, 9, guids[0], &guids)
                    .open(Arc::clone(&reads), Fault::None),
            ),
            2 => leaves.push(
                Member::new(Endian::Little, false, 9, 9999, &guids)
                    .open(Arc::clone(&reads), Fault::None),
            ),
            _ => {
                leaves.push(
                    Member::new(Endian::Little, false, 9, guids[1], &guids)
                        .open(Arc::clone(&reads), Fault::None),
                );
                if case == 4 {
                    leaves.push(leaves[0].clone());
                }
            }
        }
        let pool = Pool::from_leaves(leaves).unwrap();
        assert!(
            pool.root(&cx, 0, 2, if case == 3 { 124 } else { 123 })
                .is_err()
        );
        assert!(payload_reads(&reads, &offsets).is_empty(), "case {case}");
    }
    let leaf =
        Member::new(Endian::Little, false, 9, guids[0], &guids).open(Arc::default(), Fault::None);
    assert!(Pool::from_leaves(vec![leaf; 9]).is_err());
}

#[test]
fn conflicting_labels_candidates_and_unsupported_topology_fail_before_data_io() {
    let cx = Cx::for_testing();
    let guids = [1001, 1002];
    for case in 0..13 {
        let first = Member::new(Endian::Little, false, 9, guids[0], &guids);
        let mut second = Member::new(Endian::Little, false, 9, guids[1], &guids);
        let offsets = [BASE as u64 + first.first, BASE as u64 + first.second];
        let mut config = NvList::parse(&second.config).unwrap();
        match case {
            0 => {
                config.fields.insert("txg".into(), Value::Unsigned(43));
            }
            1 => {
                config
                    .fields
                    .insert("guid".into(), Value::Unsigned(guids[0]));
            }
            2 => {
                config.fields.insert("state".into(), Value::Unsigned(0));
            }
            3 => {
                config
                    .fields
                    .insert("vdev_children".into(), Value::Unsigned(2));
            }
            4 => {
                config
                    .fields
                    .insert("top_guid".into(), Value::Unsigned(999));
            }
            5 => {
                let Some(Value::List(tree)) = config.fields.get_mut("vdev_tree") else {
                    panic!("tree");
                };
                tree.fields
                    .insert("type".into(), Value::String("raidz".into()));
            }
            6..=9 => {
                let Some(Value::List(tree)) = config.fields.get_mut("vdev_tree") else {
                    panic!("tree");
                };
                let Some(Value::Lists(children)) = tree.fields.get_mut("children") else {
                    panic!("children");
                };
                match case {
                    6 => {
                        children[1].fields.insert("id".into(), Value::Unsigned(3));
                    }
                    7 => {
                        children[1]
                            .fields
                            .insert("guid".into(), Value::Unsigned(guids[0]));
                    }
                    8 => {
                        children[1]
                            .fields
                            .insert("offline".into(), Value::Unsigned(1));
                    }
                    _ => {
                        children[1]
                            .fields
                            .insert("type".into(), Value::String("replacing".into()));
                    }
                }
            }
            10 => {
                second.uberblock[32..40].copy_from_slice(&Endian::Little.encode(1_700_000_001));
            }
            11 => {
                second.uberblock[120..128].copy_from_slice(&Endian::Little.encode(43));
            }
            _ => {
                second.uberblock[24..32].copy_from_slice(&Endian::Little.encode(0));
            }
        }
        second.config = repack(&config);
        second.labels();
        // Case 1 also proves that agreement among most labels is insufficient.
        if case == 1 {
            second.config = native_config(
                guids[1],
                &guids,
                9,
                LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES,
                42,
            );
            let offset = LABEL_CONFIG_OFFSET;
            let mut raw = vec![0; LABEL_CONFIG_BYTES];
            raw[..second.config.len()].copy_from_slice(&second.config);
            stamp(&mut raw, offset, second.order);
            second.bytes[BASE + offset as usize..BASE + offset as usize + raw.len()]
                .copy_from_slice(&raw);
        }
        let reads: Reads = Arc::default();
        let pool = Pool::from_leaves(vec![
            first.open(Arc::clone(&reads), Fault::None),
            second.open(Arc::clone(&reads), Fault::None),
        ])
        .unwrap();
        assert!(pool.root(&cx, 0, 2, 123).is_err(), "case {case}");
        assert!(payload_reads(&reads, &offsets).is_empty(), "case {case}");
    }
}

#[test]
fn every_member_geometry_and_every_dva_are_validated_before_good_copy_success() {
    let cx = Cx::for_testing();
    let guids = [1001, 1002];
    for case in 0..5 {
        let mut first = Member::new(Endian::Little, true, 12, guids[0], &guids);
        let mut second = Member::new(Endian::Little, true, 12, guids[1], &guids);
        let offsets = [BASE as u64 + first.first, BASE as u64 + first.second];
        if case == 0 {
            second.length -= LABEL_BYTES;
            second.labels();
        } else {
            let (at, value) = match case {
                1 => (56, 8 | (1 << 32)), // Foreign second DVA, even if first is good.
                2 => (56, 16),            // Incorrectly multiplied mirror allocation.
                3 => (64, 1),             // Second DVA is not aligned to ashift.
                _ => (64, 1_u64 << 40),   // Second DVA exceeds every selected member.
            };
            for member in [&mut first, &mut second] {
                member.uberblock[at..at + 8].copy_from_slice(&member.order.encode(value));
                member.labels();
            }
        }
        let reads: Reads = Arc::default();
        let pool = Pool::from_leaves(vec![
            first.open(Arc::clone(&reads), Fault::None),
            second.open(Arc::clone(&reads), Fault::None),
        ])
        .unwrap();
        assert!(pool.root(&cx, 0, 2, 123).is_err(), "case {case}");
        assert!(payload_reads(&reads, &offsets).is_empty(), "case {case}");
    }
}

#[test]
fn unequal_selected_member_lengths_are_admitted_when_all_cover_the_configured_asize() {
    let cx = Cx::for_testing();
    let guids = [1001, 1002];
    let first = Member::new(Endian::Big, false, 9, guids[0], &guids);
    let expected = first.root.clone();
    let mut second = Member::new(Endian::Big, false, 9, guids[1], &guids);
    second.length += LABEL_BYTES;
    second
        .bytes
        .resize(BASE + second.length as usize + 512, 0x5a);
    second.labels();
    let pool = Pool::from_leaves(vec![
        first.open(Arc::default(), Fault::None),
        second.open(Arc::default(), Fault::None),
    ])
    .unwrap();
    assert_eq!(pool.root(&cx, 0, 2, 123).unwrap().data, expected);
}
