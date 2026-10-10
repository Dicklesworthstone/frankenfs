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
