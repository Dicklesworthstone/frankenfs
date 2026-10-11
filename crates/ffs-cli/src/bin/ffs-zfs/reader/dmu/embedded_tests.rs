//! Constructed DMU graphs isolate embedded traversal from label verification.
//! These are not a native pool/interchange result.

use super::*;
use crate::reader::{DATA_OFFSET, LABEL_BYTES, Value, supported_read_feature};
use ffs_block::ByteDevice;
use ffs_types::ByteOffset;
use std::sync::atomic::{AtomicUsize, Ordering};

const LEAF_BYTES: u64 = 8 * 1024 * 1024;

struct NoDataIo(Arc<AtomicUsize>);
impl ByteDevice for NoDataIo {
    fn len_bytes(&self) -> u64 {
        LEAF_BYTES
    }
    fn read_exact_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &mut [u8]) -> Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(corrupt("embedded block attempted physical I/O"))
    }
    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }
    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)
    }
}

fn embedded_raw(byte: u8, order: Endian, extra_flags: u64) -> [u8; 128] {
    // Native length-prefixed LZ4: one literal, distance-one match, five literals.
    let payload = [0, 0, 0, 12, 0x1f, byte, 1, 0, 255, 232, 0x50, byte, byte, byte, byte, byte];
    let mut words = [0_u64; 16];
    words[0] = u64::from_le_bytes(payload[..8].try_into().unwrap());
    words[1] = u64::from_le_bytes(payload[8..].try_into().unwrap());
    words[6] = 511
        | (15 << 25)
        | (15 << 32)
        | (1 << 39)
        | (19 << 48)
        | (u64::from(order == Endian::Little) << 63)
        | extra_flags;
    words[10] = 20;
    let mut raw = [0; 128];
    for (i, word) in words.into_iter().enumerate() {
        raw[i * 8..i * 8 + 8].copy_from_slice(&order.encode(word));
    }
    raw
}

fn view(leaf: &Leaf, order: Endian, extra_flags: u64) -> Objects<'_> {
    // Three level-zero pointers: embedded A, a hole, embedded B.
    let mut raw = [0; 512];
    raw[0] = 19;
    raw[1] = 12;
    raw[2] = 1;
    raw[3] = 3;
    raw[7] = 1;
    let sectors = match order {
        Endian::Little => 1_u16.to_le_bytes(),
        Endian::Big => 1_u16.to_be_bytes(),
    };
    raw[8..10].copy_from_slice(&sectors);
    raw[16..24].copy_from_slice(&order.encode(2));
    raw[64..192].copy_from_slice(&embedded_raw(b'A', order, extra_flags));
    raw[320..448].copy_from_slice(&embedded_raw(b'B', order, 0));
    Objects {
        leaf,
        config: SingleLeaf {
            pool_guid: 123,
            leaf_guid: 999,
            version: 5000,
            txg: 42,
            ashift: 9,
            id: 0,
            allocated_bytes: LEAF_BYTES - DATA_OFFSET - 2 * LABEL_BYTES,
            read_features: vec![
                "com.delphix:embedded_data".into(),
                "org.illumos:lz4_compress".into(),
            ],
        },
        txg: 42,
        root_birth: 40,
        meta: Dnode::parse(&raw, order).unwrap(),
        cache: VecDeque::new(),
        cached_bytes: 0,
    }
}

fn leaf(reads: &Arc<AtomicUsize>) -> Leaf {
    Leaf::from_device(
        &Cx::for_testing(),
        Box::new(NoDataIo(Arc::clone(reads))),
        0,
        LEAF_BYTES,
    )
    .unwrap()
}

#[test]
fn embedded_ranges_cross_holes_without_data_io_and_share_the_bounded_cache() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        let reads = Arc::new(AtomicUsize::new(0));
        let leaf = leaf(&reads);
        let mut objects = view(&leaf, order, 0);
        let expected = [vec![b'A'; 5], vec![0; 512], vec![b'B'; 5]].concat();
        assert_eq!(objects.read(&cx, 0, 507, 522).unwrap(), expected);
        assert_eq!(objects.read(&cx, 0, 507, 522).unwrap(), expected);
        assert_eq!(objects.cache.len(), 2);
        assert_eq!(objects.cached_bytes, 1024);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn embedded_cache_never_bypasses_feature_or_parent_interpretation_checks() {
    let cx = Cx::for_testing();
    let reads = Arc::new(AtomicUsize::new(0));
    let leaf = leaf(&reads);
    let mut objects = view(&leaf, Endian::Little, 0);
    objects.read(&cx, 0, 0, 512).unwrap();
    let bp = objects.meta.pointers()[0].clone();
    assert!(objects.checked(&cx, &bp, 18, 0, 512, 40).is_err());
    assert!(objects.checked(&cx, &bp, 19, 1, 512, 40).is_err());
    assert!(objects.checked(&cx, &bp, 19, 0, 1024, 40).is_err());
    assert!(objects.checked(&cx, &bp, 19, 0, 512, 19).is_err());
    objects.txg = 19;
    assert!(objects.checked(&cx, &bp, 19, 0, 512, 40).is_err());
    objects.txg = 42;
    objects.config.version = 28;
    assert!(objects.read(&cx, 0, 0, 512).is_err());
    objects.config.version = 5000;
    objects.config.read_features.clear();
    assert!(objects.read(&cx, 0, 0, 512).is_err());
    assert_eq!(reads.load(Ordering::SeqCst), 0);
}

#[test]
fn embedded_redacted_and_protected_payloads_are_errors_not_holes() {
    let cx = Cx::for_testing();
    let reads = Arc::new(AtomicUsize::new(0));
    let leaf = leaf(&reads);
    for flags in [1_u64 << 40, 2_u64 << 40, 1_u64 << 61, 1_u64 << 62] {
        let mut objects = view(&leaf, Endian::Little, flags);
        assert!(objects.read(&cx, 0, 0, 512).is_err());
        assert!(objects.cache.is_empty());
    }
    assert_eq!(reads.load(Ordering::SeqCst), 0);
}

#[test]
fn label_feature_whitelist_preserves_typed_fail_closed_admission() {
    for name in ["com.delphix:embedded_data", "org.illumos:lz4_compress"] {
        assert!(supported_read_feature(name, &Value::Boolean(true)));
        assert!(!supported_read_feature(name, &Value::Boolean(false)));
        assert!(!supported_read_feature(name, &Value::Unsigned(1)));
    }
    for name in ["com.datto:encryption", "com.delphix:redacted_datasets", "unknown:feature"] {
        assert!(!supported_read_feature(name, &Value::Boolean(true)));
    }
}
