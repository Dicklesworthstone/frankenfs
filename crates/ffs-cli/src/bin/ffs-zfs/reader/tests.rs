use super::*;
use ffs_ondisk::zfs::checksum;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

const BASE: usize = 1024;
const LENGTH: usize = 8 * 1024 * 1024;
const FIRST: u64 = DATA_OFFSET + 4096;
const SECOND: u64 = DATA_OFFSET + 8192;
type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

fn xstring(value: &str) -> Vec<u8> {
    let mut bytes = (value.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(value.as_bytes());
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}
fn pair(name: &str, kind: u32, data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 8];
    bytes.extend_from_slice(&xstring(name));
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(data);
    let length = bytes.len() as u32;
    bytes[..4].copy_from_slice(&length.to_be_bytes());
    bytes[4..8].copy_from_slice(&64_u32.to_be_bytes());
    bytes
}
fn uint(name: &str, value: u64) -> Vec<u8> {
    pair(name, 8, &value.to_be_bytes())
}
fn presence(name: &str) -> Vec<u8> {
    let mut bytes = pair(name, 1, &[]);
    let end = bytes.len();
    bytes[end - 4..].fill(0); // Native DATA_TYPE_BOOLEAN has zero elements.
    bytes
}
fn list(pairs: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, 0, 0, 0, 0, 1];
    for pair in pairs {
        bytes.extend_from_slice(pair);
    }
    bytes.extend_from_slice(&[0; 8]);
    bytes
}
fn config(guid: u64, ashift: u64, state: u64, feature: bool) -> Vec<u8> {
    let features = if feature {
        list(&[presence("unknown:required_feature")])
    } else {
        list(&[])
    };
    config_features(guid, ashift, state, &features)
}
fn config_features(guid: u64, ashift: u64, state: u64, features: &[u8]) -> Vec<u8> {
    let tree = list(&[
        pair("type", 9, &xstring("file")),
        uint("id", 0),
        uint("guid", guid),
        uint("ashift", ashift),
        uint("asize", LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES),
        uint("is_log", 0),
    ]);
    let mut bytes = vec![1, 1, 0, 0];
    bytes.extend_from_slice(&list(&[
        uint("version", 5000),
        uint("state", state),
        uint("txg", 42),
        uint("pool_guid", 123),
        uint("guid", guid),
        uint("top_guid", guid),
        uint("vdev_children", 1),
        pair("name", 9, &xstring("fixture")),
        pair("vdev_tree", 19, &tree),
        pair("features_for_read", 19, features),
    ]));
    bytes
}
fn stamp(bytes: &mut [u8], offset: u64, order: Endian) {
    let at = bytes.len() - 40;
    bytes[at..at + 8].copy_from_slice(&order.encode(0x0210_da7a_b10c_7a11));
    bytes[at + 8..].fill(0);
    bytes[at + 8..at + 16].copy_from_slice(&order.encode(offset));
    let digest = Sha256::digest(&*bytes);
    for i in 0..4 {
        let word = u64::from_be_bytes(std::array::from_fn(|n| digest[i * 8 + n]));
        bytes[at + 8 + i * 8..at + 16 + i * 8].copy_from_slice(&order.encode(word));
    }
}
fn from_hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect()
}
struct Image {
    bytes: Vec<u8>,
    order: Endian,
    root: Vec<u8>,
}
impl Image {
    fn new(order: Endian, compressed: bool) -> Self {
        let mut root = vec![0; 1024];
        root[704..712].copy_from_slice(&order.encode(1));
        // Generated independently with the system liblz4 compressor, not this reader.
        let mut physical = if compressed {
            from_hex(match order {
                Endian::Little => "000000131f000100ffffae1f01c002ff28500000000000",
                Endian::Big => "000000131f000100ffffb51f01c702ff21500000000000",
            })
        } else {
            root.clone()
        };
        if compressed {
            physical.resize(512, 0);
        }
        let mut bp = [0_u64; 16];
        bp[0] = physical.len() as u64 / 512;
        bp[1] = 8;
        bp[2] = physical.len() as u64 / 512;
        bp[3] = 16;
        bp[6] = 1
            | ((physical.len() as u64 / 512 - 1) << 16)
            | (u64::from(if compressed { 15_u8 } else { 2 }) << 32)
            | (7 << 40)
            | (11 << 48)
            | (u64::from(order == Endian::Little) << 63);
        bp[10] = 42;
        bp[12..].copy_from_slice(&checksum(&physical, 7, order).unwrap());
        let mut ub = vec![0; 1024];
        for (at, value) in [
            (0, 0x00ba_b10c),
            (8, 5000),
            (16, 43),
            (24, 1122),
            (32, 1_700_000_000),
        ] {
            ub[at..at + 8].copy_from_slice(&order.encode(value));
        }
        for (i, word) in bp.into_iter().enumerate() {
            ub[40 + i * 8..48 + i * 8].copy_from_slice(&order.encode(word));
        }
        let mut image = Self {
            bytes: vec![0; BASE + LENGTH + 512],
            order,
            root,
        };
        image.bytes[..BASE].fill(0xA1);
        image.bytes[BASE + LENGTH..].fill(0xB2);
        for index in 0..4 {
            image.set_config(index, &config(999, 9, 1, false));
            let label = label_offsets(LENGTH as u64).unwrap()[index];
            let offset = label + UBERBLOCK_RING_OFFSET + 2 * 1024;
            let mut block = ub.clone();
            stamp(&mut block, offset, order);
            let start = BASE + offset as usize;
            image.bytes[start..start + 1024].copy_from_slice(&block);
        }
        for offset in [FIRST, SECOND] {
            let start = BASE + offset as usize;
            image.bytes[start..start + physical.len()].copy_from_slice(&physical);
        }
        image
    }
    fn set_config(&mut self, index: usize, packed: &[u8]) {
        let offset = label_offsets(LENGTH as u64).unwrap()[index] + LABEL_CONFIG_OFFSET;
        let mut bytes = vec![0; LABEL_CONFIG_BYTES];
        bytes[..packed.len()].copy_from_slice(packed);
        stamp(&mut bytes, offset, self.order);
        let at = BASE + offset as usize;
        self.bytes[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    fn change_dva(&mut self, word: usize, value: u64) {
        let offset = UBERBLOCK_RING_OFFSET + 2 * 1024;
        let at = BASE + offset as usize;
        let ub = &mut self.bytes[at..at + 1024];
        ub[40 + word * 8..48 + word * 8].copy_from_slice(&self.order.encode(value));
        stamp(ub, offset, self.order);
    }
    fn replicate_candidate(&mut self) {
        let at = BASE + UBERBLOCK_RING_OFFSET as usize + 2 * 1024;
        let candidate = self.bytes[at..at + 1024].to_vec();
        for label in label_offsets(LENGTH as u64).unwrap().into_iter().skip(1) {
            let offset = label + UBERBLOCK_RING_OFFSET + 2 * 1024;
            let mut copy = candidate.clone();
            stamp(&mut copy, offset, self.order);
            let at = BASE + offset as usize;
            self.bytes[at..at + copy.len()].copy_from_slice(&copy);
        }
    }
    fn open(self, reads: Reads, failure: Option<u64>) -> Leaf {
        Leaf::from_device(
            &Cx::for_testing(),
            Box::new(Memory {
                bytes: self.bytes,
                reads,
                failure,
            }),
            BASE as u64,
            LENGTH as u64,
        )
        .unwrap()
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
    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push((offset.0, bytes.len()));
        if self.failure == Some(offset.0) {
            return Err(FfsError::Cancelled);
        }
        let start = usize::try_from(offset.0).map_err(|_| corrupt("offset overflow"))?;
        let end = start
            .checked_add(bytes.len())
            .ok_or_else(|| corrupt("span overflow"))?;
        bytes.copy_from_slice(
            self.bytes
                .get(start..end)
                .ok_or_else(|| corrupt("short test device"))?,
        );
        Ok(())
    }
    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> Result<()> {
        panic!("ZFS read attempted a write");
    }
    fn sync(&self, _cx: &Cx) -> Result<()> {
        panic!("ZFS read attempted a flush");
    }
}
fn data_reads(reads: &Reads) -> Vec<u64> {
    reads
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(offset, _)| {
            [BASE as u64 + FIRST, BASE as u64 + SECOND]
                .contains(offset)
                .then_some(*offset)
        })
        .collect()
}

#[test]
fn both_orders_and_native_lz4_roots_read_through_selected_partition() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for compressed in [false, true] {
            let image = Image::new(order, compressed);
            let expected = image.root.clone();
            let leaf = image.open(Arc::default(), None);
            for index in 0..4 {
                let label = leaf.label(&cx, index).unwrap();
                assert_eq!(label.config.unsigned("pool_guid"), Some(123));
                assert_eq!(label.slot_bytes, 1024);
                let result = leaf.root(&cx, index, 2, 123).unwrap();
                assert_eq!(result.data, expected);
                assert_eq!(result.uberblock.txg, 43);
                assert_eq!((result.physical_offset, result.copy_index), (FIRST, 0));
            }
            assert!(leaf.root(&cx, 0, 128, 123).is_err());
            assert!(leaf.root(&cx, 4, 2, 123).is_err());
        }
    }
}
#[test]
fn bad_copy_retries_but_cancel_does_not() {
    let cx = Cx::for_testing();
    let mut image = Image::new(Endian::Little, true);
    image.bytes[BASE + FIRST as usize + 21] ^= 1;
    let expected = image.root.clone();
    let reads: Reads = Arc::default();
    let result = image
        .open(Arc::clone(&reads), None)
        .root(&cx, 0, 2, 123)
        .unwrap();
    assert_eq!(result.data, expected);
    assert_eq!(result.copy_index, 1);
    assert_eq!(
        data_reads(&reads),
        [BASE as u64 + FIRST, BASE as u64 + SECOND]
    );
    let reads: Reads = Arc::default();
    let leaf =
        Image::new(Endian::Little, false).open(Arc::clone(&reads), Some(BASE as u64 + FIRST));
    assert!(matches!(
        leaf.root(&cx, 0, 2, 123),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(data_reads(&reads), [BASE as u64 + FIRST]);
}
#[test]
fn contradictory_labels_active_pool_and_unknown_features_fail_before_data_io() {
    let cx = Cx::for_testing();
    for case in 0..4 {
        let mut image = Image::new(Endian::Little, false);
        let packed = match case {
            0 => config(1000, 9, 1, false),
            1 => config(999, 9, 0, false),
            2 => config(999, 9, 1, true),
            _ => config(999, 12, 1, false),
        };
        image.set_config(3, &packed);
        let reads: Reads = Arc::default();
        let leaf = image.open(Arc::clone(&reads), None);
        assert!(leaf.root(&cx, 0, 2, 123).is_err());
        assert_eq!(data_reads(&reads), [] as [u64; 0]);
    }
    let reads: Reads = Arc::default();
    let leaf = Image::new(Endian::Little, false).open(Arc::clone(&reads), None);
    assert!(leaf.root(&cx, 0, 2, 456).is_err());
    assert_eq!(data_reads(&reads), [] as [u64; 0]);
}
#[test]
fn foreign_gang_oversized_and_label_overlapping_dvas_are_refused() {
    let cx = Cx::for_testing();
    for (word, value) in [
        (0, (1_u64 << 32) | 2),
        (1, (1_u64 << 63) | 8),
        (0, 3),
        (1, LENGTH as u64 / 512),
        (1, u64::MAX - 1),
    ] {
        let mut image = Image::new(Endian::Little, false);
        image.change_dva(word, value);
        let reads: Reads = Arc::default();
        let leaf = image.open(Arc::clone(&reads), None);
        assert!(leaf.root(&cx, 0, 2, 123).is_err());
        assert_eq!(data_reads(&reads), [] as [u64; 0]);
    }
}
#[test]
fn truncated_views_do_not_issue_io_and_all_corrupt_copies_fail() {
    let reads: Reads = Arc::default();
    let device = Box::new(Memory {
        bytes: vec![0; 1024],
        reads: Arc::clone(&reads),
        failure: None,
    });
    assert!(Leaf::from_device(&Cx::for_testing(), device, u64::MAX, 1024).is_err());
    assert_eq!(*reads.lock().unwrap(), [] as [(u64, usize); 0]);
    let mut image = Image::new(Endian::Little, false);
    for offset in [FIRST, SECOND] {
        image.bytes[BASE + offset as usize] ^= 1;
    }
    assert!(
        image
            .open(Arc::default(), None)
            .root(&Cx::for_testing(), 0, 2, 123)
            .is_err()
    );
}
#[test]
fn actual_image_and_neighboring_bytes_are_unchanged() {
    let image = Image::new(Endian::Little, true);
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("leaf.img");
    std::fs::write(&path, &image.bytes).unwrap();
    let cx = Cx::for_testing();
    let leaf = Leaf::open(&cx, &path, BASE as u64, Some(LENGTH as u64)).unwrap();
    assert_eq!(leaf.root(&cx, 0, 2, 123).unwrap().data, image.root);
    assert_eq!(std::fs::read(&path).unwrap(), image.bytes);
}

#[test]
fn native_boolean_features_and_uberblock_membership_are_required() {
    let cx = Cx::for_testing();
    for mistyped in [false, true] {
        let feature = if mistyped {
            uint("org.illumos:lz4_compress", 1)
        } else {
            presence("org.illumos:lz4_compress")
        };
        let packed = config_features(999, 9, 1, &list(&[feature]));
        let mut image = Image::new(Endian::Little, true);
        for label in 0..4 {
            image.set_config(label, &packed);
        }
        let expected = image.root.clone();
        let reads: Reads = Arc::default();
        let result = image.open(Arc::clone(&reads), None).root(&cx, 0, 2, 123);
        if mistyped {
            assert!(result.is_err());
            assert_eq!(data_reads(&reads), [] as [u64; 0]);
        } else {
            assert_eq!(result.unwrap().data, expected);
        }
    }
    let mut image = Image::new(Endian::Little, false);
    let offset = UBERBLOCK_RING_OFFSET + 2 * 1024;
    let at = BASE + offset as usize;
    let ub = &mut image.bytes[at..at + 1024];
    ub[24..32].copy_from_slice(&Endian::Little.encode(1123));
    stamp(ub, offset, Endian::Little); // Checksum-correct but wrong pool membership.
    let reads: Reads = Arc::default();
    assert!(
        image
            .open(Arc::clone(&reads), None)
            .root(&cx, 0, 2, 123)
            .is_err()
    );
    assert_eq!(data_reads(&reads), [] as [u64; 0]);
}

#[test]
fn embedded_data_feature_admission_retains_boolean_types_and_label_agreement() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for case in 0..4 {
            let feature = match case {
                1 => uint("com.delphix:embedded_data", 1),
                2 => presence("com.delphix:redacted_datasets"),
                _ => presence("com.delphix:embedded_data"),
            };
            let features = list(&[presence("org.illumos:lz4_compress"), feature]);
            let packed = config_features(999, 9, 1, &features);
            let mut image = Image::new(order, true);
            for label in 0..4 {
                image.set_config(label, &packed);
            }
            if case == 3 {
                let missing = list(&[presence("org.illumos:lz4_compress")]);
                image.set_config(3, &config_features(999, 9, 1, &missing));
            }
            let expected = image.root.clone();
            let reads: Reads = Arc::default();
            let leaf = image.open(Arc::clone(&reads), None);
            let result = leaf.root(&cx, 0, 2, 123);
            if case == 0 {
                assert_eq!(result.unwrap().data, expected);
                assert!(
                    leaf.label(&cx, 0)
                        .unwrap()
                        .single_leaf(123)
                        .unwrap()
                        .read_features
                        .iter()
                        .any(|feature| feature == "com.delphix:embedded_data")
                );
            } else {
                assert!(result.is_err(), "case {case}");
                assert_eq!(data_reads(&reads), [] as [u64; 0]);
            }
        }
    }
}

#[test]
fn embedded_read_feature_requires_native_boolean_and_all_label_agreement() {
    let cx = Cx::for_testing();
    let feature_name = "com.delphix:embedded_data";
    for order in [Endian::Little, Endian::Big] {
        for mistyped in [false, true] {
            let feature = if mistyped {
                uint(feature_name, 1)
            } else {
                presence(feature_name)
            };
            let packed = config_features(
                999,
                9,
                1,
                &list(&[feature, presence("org.illumos:lz4_compress")]),
            );
            let mut image = Image::new(order, true);
            for label in 0..4 {
                image.set_config(label, &packed);
            }
            let expected = image.root.clone();
            let reads: Reads = Arc::default();
            let result = image.open(Arc::clone(&reads), None).root(&cx, 0, 2, 123);
            if mistyped {
                assert!(result.is_err());
                assert_eq!(data_reads(&reads), [] as [u64; 0]);
            } else {
                assert_eq!(result.unwrap().data, expected);
            }
        }
        let mut image = Image::new(order, false);
        let packed = config_features(999, 9, 1, &list(&[presence(feature_name)]));
        for label in 0..3 {
            image.set_config(label, &packed);
        }
        // A valid fourth label lacking the feature is a contradictory catalog.
        let reads: Reads = Arc::default();
        assert!(
            image
                .open(Arc::clone(&reads), None)
                .root(&cx, 0, 2, 123)
                .is_err()
        );
        assert_eq!(data_reads(&reads), [] as [u64; 0]);
    }
}

#[test]
fn bd_glk87_auto_import_and_multi_top_level_vdev_striping_contract() {
    let cx = Cx::for_testing();
    // 1. Automatic active/exported uberblock import selects highest valid TXG across ring slots
    let mut image = Image::new(Endian::Little, false);
    // Write an active (state = 0) config and a newer uberblock at slot 5 (txg = 50)
    for index in 0..4 {
        image.set_config(index, &config(999, 9, 0, false));
    }
    let label0 = label_offsets(LENGTH as u64).unwrap()[0];
    let slot2_off = label0 + UBERBLOCK_RING_OFFSET + 2 * 1024;
    let slot5_off = label0 + UBERBLOCK_RING_OFFSET + 5 * 1024;
    let mut ub50 =
        image.bytes[BASE + slot2_off as usize..BASE + slot2_off as usize + 1024].to_vec();
    ub50[16..24].copy_from_slice(&Endian::Little.encode(50));
    ub50[32..40].copy_from_slice(&Endian::Little.encode(1_700_000_500));
    stamp(&mut ub50, slot5_off, Endian::Little);
    image.bytes[BASE + slot5_off as usize..BASE + slot5_off as usize + 1024].copy_from_slice(&ub50);

    let expected_root = image.root.clone();
    let leaf = image.open(Arc::default(), None);
    let imported = leaf.import_active(&cx, None).unwrap();
    assert_eq!(imported.2.uberblock.txg, 50);
    assert_eq!(imported.2.data, expected_root);
    assert!(leaf.import_active(&cx, Some(999_999)).is_err());

    // 2. Multi-top-level-vdev striped pool (vdev_children = 2, DVA on vdev 1)
    let mut img0 = Image::new(Endian::Little, false);
    let mut img1 = Image::new(Endian::Little, false);
    let asize = LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES;
    let make_striped_cfg = |id: u64, guid: u64, state: u64| -> Vec<u8> {
        let tree = list(&[
            pair("type", 9, &xstring("file")),
            uint("id", id),
            uint("guid", guid),
            uint("ashift", 9),
            uint("asize", asize),
            uint("is_log", 0),
        ]);
        let mut bytes = vec![1, 1, 0, 0];
        bytes.extend_from_slice(&list(&[
            uint("version", 5000),
            uint("state", state),
            uint("txg", 42),
            uint("pool_guid", 123),
            uint("guid", guid),
            uint("top_guid", guid),
            uint("vdev_children", 2),
            pair("name", 9, &xstring("striped")),
            pair("vdev_tree", 19, &tree),
            pair("features_for_read", 19, &list(&[])),
        ]));
        bytes
    };
    // Point uberblock DVA[0] and DVA[1] on both leaves to vdev 1 (word 0 and word 2 high 32 bits = 1)
    let vdev1_word = (1_u64 << 32) | (expected_root.len() as u64 / 512);
    img0.change_dva(0, vdev1_word);
    img0.change_dva(2, vdev1_word);
    img1.change_dva(0, vdev1_word);
    img1.change_dva(2, vdev1_word);
    // Every copy of a committed TXG must describe the same root. Changing
    // only label zero would manufacture a checksum-valid fork in this fixture.
    img0.replicate_candidate();
    img1.replicate_candidate();
    // Clear physical blocks on img0 so reading from vdev 0 would fail checksum
    img0.bytes[BASE + FIRST as usize..BASE + FIRST as usize + 1024].fill(0);
    img0.bytes[BASE + SECOND as usize..BASE + SECOND as usize + 1024].fill(0);

    // 2a. Exported striped pool (state = 1) works with both explicit pool.root and pool.import_active
    // Uberblock guid_sum is 1122 = pool_guid (123) + vdev0 (499) + vdev1 (500).
    let cfg0_exp = make_striped_cfg(0, 499, 1);
    let cfg1_exp = make_striped_cfg(1, 500, 1);
    for index in 0..4 {
        img0.set_config(index, &cfg0_exp);
        img1.set_config(index, &cfg1_exp);
    }
    let mut img0_active = Image {
        bytes: img0.bytes.clone(),
        order: img0.order,
        root: img0.root.clone(),
    };
    let mut img1_active = Image {
        bytes: img1.bytes.clone(),
        order: img1.order,
        root: img1.root.clone(),
    };
    let leaf0 = img0.open(Arc::default(), None);
    let leaf1 = img1.open(Arc::default(), None);
    let pool = Pool::from_leaves(vec![leaf0, leaf1]).unwrap();
    let striped_root = pool.root(&cx, 0, 2, 123).unwrap();
    assert_eq!(striped_root.data, expected_root);
    assert_eq!(striped_root.member_guid, 500);
    assert_eq!(pool.import_active(&cx, Some(123)).unwrap().2.data, expected_root);

    // 2b. Active striped pool (state = 0) works with pool.import_active
    let cfg0_act = make_striped_cfg(0, 499, 0);
    let cfg1_act = make_striped_cfg(1, 500, 0);
    for index in 0..4 {
        img0_active.set_config(index, &cfg0_act);
        img1_active.set_config(index, &cfg1_act);
    }
    // Only the second supplied member retains uberblocks. Data routing must
    // still use native vdev IDs, independently of the ring's physical source.
    for label in label_offsets(LENGTH as u64).unwrap() {
        let at = BASE + (label + UBERBLOCK_RING_OFFSET) as usize;
        img0_active.bytes[at..at + UBERBLOCK_RING_BYTES].fill(0);
    }
    let pool_active = Pool::from_leaves(vec![
        img0_active.open(Arc::default(), None),
        img1_active.open(Arc::default(), None),
    ])
    .unwrap();
    let auto_striped = pool_active.import_active(&cx, Some(123)).unwrap();
    assert_eq!(auto_striped.2.data, expected_root);
    assert_eq!(auto_striped.2.member_guid, 500);
}

#[test]
fn auto_import_single_leaf_uses_one_config_and_independently_verified_rings() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for survivor in 0..4 {
            let mut image = Image::new(order, false);
            let source = BASE + UBERBLOCK_RING_OFFSET as usize + 2 * 1024;
            let mut candidate = image.bytes[source..source + 1024].to_vec();
            let labels = label_offsets(LENGTH as u64).unwrap();
            for (index, label) in labels.into_iter().enumerate() {
                if index != survivor {
                    let at = BASE + (label + LABEL_CONFIG_OFFSET) as usize;
                    image.bytes[at] ^= 1;
                }
                let at = BASE + (label + UBERBLOCK_RING_OFFSET) as usize;
                image.bytes[at..at + UBERBLOCK_RING_BYTES].fill(0);
            }
            let ring = (survivor + 1) % 4;
            let offset = labels[ring] + UBERBLOCK_RING_OFFSET + 7 * 1024;
            stamp(&mut candidate, offset, order);
            let at = BASE + offset as usize;
            image.bytes[at..at + candidate.len()].copy_from_slice(&candidate);
            let expected = image.root.clone();
            let leaf = image.open(Arc::default(), None);
            assert!(leaf.root(&cx, survivor, 2, 123).is_err());
            let (label, slot, root) = leaf.import_active(&cx, Some(123)).unwrap();
            assert_eq!((label, slot), (ring, 7));
            assert_eq!(root.data, expected);
        }
    }
}

#[test]
fn auto_import_single_leaf_preserves_device_cancellation() {
    for offset in [LABEL_CONFIG_OFFSET, UBERBLOCK_RING_OFFSET + 1024] {
        let reads: Reads = Arc::default();
        let leaf = Image::new(Endian::Little, false)
            .open(Arc::clone(&reads), Some(BASE as u64 + offset));
        assert!(matches!(
            leaf.import_active(&Cx::for_testing(), None),
            Err(FfsError::Cancelled)
        ));
        assert!(data_reads(&reads).is_empty());
    }
}

#[test]
fn auto_import_single_leaf_does_not_hide_valid_bad_metadata() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for case in 0..4 {
            let mut image = Image::new(order, false);
            match case {
                0 => image.set_config(3, &config(1000, 9, 1, false)),
                1 => image.set_config(3, &config(999, 9, 1, true)),
                2 => image.set_config(3, &config(999, 12, 1, false)),
                _ => {
                    let offset = label_offsets(LENGTH as u64).unwrap()[3] + LABEL_CONFIG_OFFSET;
                    let at = BASE + offset as usize;
                    let raw = &mut image.bytes[at..at + LABEL_CONFIG_BYTES];
                    raw[0] = 2; // Unsupported nvlist encoding, with a valid label checksum.
                    stamp(raw, offset, order);
                }
            }
            let reads: Reads = Arc::default();
            let leaf = image.open(Arc::clone(&reads), None);
            assert!(leaf.import_active(&cx, None).is_err(), "case {case}");
            assert!(data_reads(&reads).is_empty());
        }
    }
}

#[test]
fn auto_import_expected_pool_identity_is_checked_before_data_io() {
    let reads: Reads = Arc::default();
    let leaf = Image::new(Endian::Little, false).open(Arc::clone(&reads), None);
    assert!(leaf.import_active(&Cx::for_testing(), Some(456)).is_err());
    assert!(data_reads(&reads).is_empty());
}

#[test]
fn auto_import_does_not_rewrite_bad_labels_or_partition_neighbors() {
    let mut image = Image::new(Endian::Little, false);
    image.bytes[BASE + LABEL_CONFIG_OFFSET as usize] ^= 1;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("damaged-label.img");
    std::fs::write(&path, &image.bytes).unwrap();
    let cx = Cx::for_testing();
    let leaf = Leaf::open(&cx, &path, BASE as u64, Some(LENGTH as u64)).unwrap();
    assert_eq!(leaf.import_active(&cx, None).unwrap().2.data, image.root);
    assert_eq!(std::fs::read(&path).unwrap(), image.bytes);
}

pub(in crate::reader) mod gang;
pub(in crate::reader) mod mirror;
pub(in crate::reader) mod raidz;
