//! Constructed native labels and checksummed roots, not OpenZFS import proof.

use super::*;
use crate::reader::tests::mirror::{
    Fault, MIRROR_GUID, install_labels, native_config, open_bytes, repack,
};
use crate::reader::{FfsError, NvList, Value};
use ffs_ondisk::zfs::{DATA_OFFSET, Endian, LABEL_BYTES, checksum};
use std::sync::{Arc, Mutex};

const BASE: usize = 1024;
const LENGTH: usize = 8 * 1024 * 1024;
const FIRST: u64 = DATA_OFFSET + 4096;
const SECOND: u64 = DATA_OFFSET + 8192;
type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

struct Image {
    bytes: Vec<u8>,
    root: Vec<u8>,
    config: Vec<u8>,
    uberblock: Vec<u8>,
    order: Endian,
}

impl Image {
    fn new(order: Endian, guid: u64, all: &[u64]) -> Self {
        let mut root = vec![0; 1024];
        root[704..712].copy_from_slice(&order.encode(1));
        let mut bp = [0_u64; 16];
        bp[0] = 2;
        bp[1] = 8;
        bp[2] = 2;
        bp[3] = 16;
        bp[6] = 1
            | (1 << 16)
            | (2 << 32)
            | (7 << 40)
            | (11 << 48)
            | (u64::from(order == Endian::Little) << 63);
        bp[10] = 42;
        bp[12..].copy_from_slice(&checksum(&root, 7, order).unwrap());
        let mut uberblock = vec![0; 1024];
        let guid_sum = all
            .iter()
            .fold(123_u64 + MIRROR_GUID, |sum, guid| sum.wrapping_add(*guid));
        for (at, value) in [
            (0, 0x00ba_b10c),
            (8, 5000),
            (16, 43),
            (24, guid_sum),
            (32, 1_700_000_000),
        ] {
            uberblock[at..at + 8].copy_from_slice(&order.encode(value));
        }
        for (i, word) in bp.into_iter().enumerate() {
            uberblock[40 + i * 8..48 + i * 8].copy_from_slice(&order.encode(word));
        }
        let config = native_config(
            guid,
            all,
            9,
            LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES,
            42,
        );
        let mut bytes = vec![0; BASE + LENGTH + 512];
        bytes[..BASE].fill(0xA1);
        bytes[BASE + LENGTH..].fill(0xB2);
        for offset in [FIRST, SECOND] {
            let at = BASE + offset as usize;
            bytes[at..at + root.len()].copy_from_slice(&root);
        }
        let mut image = Self {
            bytes,
            root,
            config,
            uberblock,
            order,
        };
        image.labels();
        image
    }

    fn labels(&mut self) {
        install_labels(
            &mut self.bytes,
            BASE,
            LENGTH as u64,
            self.order,
            &self.config,
            &self.uberblock,
        );
    }

    fn open(self, reads: &Reads, fault: Fault) -> Leaf {
        // The fixture device panics on any write or sync, including failed opens.
        open_bytes(self.bytes, BASE, LENGTH as u64, Arc::clone(reads), fault)
    }
}

fn payload_reads(reads: &Reads) -> usize {
    reads
        .lock()
        .unwrap()
        .iter()
        .filter(|(at, _)| *at == BASE as u64 + FIRST || *at == BASE as u64 + SECOND)
        .count()
}

#[test]
fn explicit_missing_mirrors_read_one_or_many_survivors_without_becoming_standalone() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for width in [2_u64, 3, 8] {
            let all: Vec<_> = (1001..1001 + width).collect();
            for survivors in [1, all.len() - 1] {
                let reads: Reads = Arc::default();
                let image = Image::new(order, all[0], &all);
                let expected = image.root.clone();
                let leaves = all[..survivors]
                    .iter()
                    .rev()
                    .map(|guid| Image::new(order, *guid, &all).open(&reads, Fault::None))
                    .collect();
                let pool =
                    Pool::from_mirror_survivors(&cx, leaves, all[survivors..].to_vec()).unwrap();
                assert!(pool.standalone_leaf().is_none());
                assert_eq!(payload_reads(&reads), 0);
                let owner = pool.clone();
                drop(pool);
                let root = owner.root(&cx, 0, 2, 123).unwrap();
                assert_eq!(root.data, expected);
                assert_eq!(root.member_guid, all[survivors - 1]);
                assert_eq!(
                    root.uberblock.guid_sum,
                    all.iter().sum::<u64>() + 123 + MIRROR_GUID
                );
                assert!(owner.root(&cx, 0, 2, 124).is_err());
                assert!(owner.root_with_mode(&cx, 0, 2, 123, true).is_err());
                // Even the library path must not silently select a newer/older TXG.
                assert!(owner.import_active(&cx, Some(123)).is_err());
                assert!(reads.lock().unwrap().iter().all(|(at, size)| {
                    *at >= BASE as u64 && *at + *size as u64 <= (BASE + LENGTH) as u64
                }));
            }
        }
    }
}

#[test]
fn complete_member_mode_still_refuses_an_omitted_mirror_disk() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    for supplied in [1, 2] {
        let all = [1001, 1002, 1003];
        let leaves = all[..supplied]
            .iter()
            .map(|guid| Image::new(Endian::Little, *guid, &all).open(&reads, Fault::None))
            .collect();
        assert!(
            Pool::from_leaves(leaves)
                .unwrap()
                .root(&cx, 0, 2, 123)
                .is_err()
        );
    }
    assert_eq!(payload_reads(&reads), 0);
}

#[test]
fn missing_mirror_requests_reject_unknown_duplicate_present_and_unlisted_guids() {
    let cx = Cx::for_testing();
    for missing in [
        vec![],
        vec![0],
        vec![1002, 1002],
        vec![1001, 1003],
        vec![9999, 1003],
        vec![1002],
    ] {
        let reads: Reads = Arc::default();
        let leaf = Image::new(Endian::Little, 1001, &[1001, 1002, 1003]).open(&reads, Fault::None);
        assert!(Pool::from_mirror_survivors(&cx, vec![leaf], missing).is_err());
        assert_eq!(payload_reads(&reads), 0);
    }
    for (supplied, missing) in [
        (0, vec![1]),
        (8, vec![1]),
        (1, vec![1; 8]),
        (usize::MAX, vec![1]),
    ] {
        assert!(Pool::check_mirror_survivors(supplied, &missing).is_err());
    }
    let reads: Reads = Arc::default();
    let repeated = (0..2)
        .map(|_| Image::new(Endian::Little, 1001, &[1001, 1002, 1003]).open(&reads, Fault::None))
        .collect();
    assert!(Pool::from_mirror_survivors(&cx, repeated, vec![1002]).is_err());
    assert_eq!(payload_reads(&reads), 0);
}

#[test]
fn missing_mirror_refuses_active_raidz_and_inconsistent_surviving_labels() {
    let cx = Cx::for_testing();
    for case in 0..4 {
        let reads: Reads = Arc::default();
        let mut image = Image::new(Endian::Little, 1001, &[1001, 1002]);
        let mut config = NvList::parse_exact(&image.config).unwrap();
        match case {
            0 => {
                config.fields.insert("state".into(), Value::Unsigned(0));
            }
            1 => {
                let Value::List(tree) = config.fields.get_mut("vdev_tree").unwrap() else {
                    panic!("tree");
                };
                tree.fields
                    .insert("type".into(), Value::String("raidz".into()));
                tree.fields.insert("nparity".into(), Value::Unsigned(1));
            }
            2 => {
                config
                    .fields
                    .insert("vdev_children".into(), Value::Unsigned(2));
            }
            _ => {
                config.fields.insert("txg".into(), Value::Unsigned(41));
            }
        }
        image.config = repack(&config);
        if case == 3 {
            // Change only label zero, with a valid checksum; no majority vote.
            let original = image.bytes.clone();
            image.labels();
            image.bytes[BASE + LABEL_BYTES as usize..]
                .copy_from_slice(&original[BASE + LABEL_BYTES as usize..]);
        } else {
            image.labels();
        }
        assert!(
            Pool::from_mirror_survivors(&cx, vec![image.open(&reads, Fault::None)], vec![1002])
                .is_err()
        );
        assert_eq!(payload_reads(&reads), 0);
    }
}

#[test]
fn missing_mirror_keeps_full_guid_sum_and_rejects_conflicting_candidates_before_payload() {
    let cx = Cx::for_testing();
    for wrong_sum in [true, false] {
        let reads: Reads = Arc::default();
        let all = [1001, 1002, 1003];
        let first = Image::new(Endian::Little, 1001, &all);
        let mut second = Image::new(Endian::Little, 1002, &all);
        let at = if wrong_sum { 24 } else { 32 };
        let value = if wrong_sum {
            123 + MIRROR_GUID + 1001 + 1002
        } else {
            1_700_000_001
        };
        second.uberblock[at..at + 8].copy_from_slice(&Endian::Little.encode(value));
        second.labels();
        let pool = Pool::from_mirror_survivors(
            &cx,
            vec![
                second.open(&reads, Fault::None),
                first.open(&reads, Fault::None),
            ],
            vec![1003],
        )
        .unwrap();
        assert!(pool.root(&cx, 0, 2, 123).is_err());
        assert_eq!(payload_reads(&reads), 0);
    }
}

#[test]
fn missing_mirror_retries_verified_copies_but_cancellation_is_terminal() {
    let cx = Cx::for_testing();
    let all = [1001, 1002, 1003];
    for cancel in [false, true] {
        let first_reads: Reads = Arc::default();
        let second_reads: Reads = Arc::default();
        let first = Image::new(Endian::Little, 1001, &all);
        let second = Image::new(Endian::Little, 1002, &all);
        let expected = second.root.clone();
        let fault = if cancel {
            Fault::Cancel(BASE as u64 + FIRST)
        } else {
            Fault::Io(BASE as u64 + FIRST)
        };
        let pool = Pool::from_mirror_survivors(
            &cx,
            vec![
                first.open(&first_reads, fault),
                second.open(&second_reads, Fault::None),
            ],
            vec![1003],
        )
        .unwrap();
        let result = pool.root(&cx, 0, 2, 123);
        if cancel {
            assert!(matches!(result, Err(FfsError::Cancelled)));
            assert_eq!(payload_reads(&second_reads), 0);
        } else {
            let root = result.unwrap();
            assert_eq!(root.data, expected);
            assert_eq!(root.member_guid, 1002);
            assert_eq!(root.copy_index, 0);
            assert_eq!(payload_reads(&second_reads), 1);
        }
    }
    for bad_copies in [1, 2] {
        let reads: Reads = Arc::default();
        let mut image = Image::new(Endian::Big, 1002, &[1001, 1002]);
        for offset in [FIRST, SECOND].into_iter().take(bad_copies) {
            image.bytes[BASE + offset as usize] ^= 1;
        }
        let expected = image.root.clone();
        let pool =
            Pool::from_mirror_survivors(&cx, vec![image.open(&reads, Fault::None)], vec![1001])
                .unwrap();
        let result = pool.root(&cx, 0, 2, 123);
        if bad_copies == 1 {
            let root = result.unwrap();
            assert_eq!(root.data, expected);
            assert_eq!(root.copy_index, 1);
        } else {
            assert!(result.is_err());
        }
        assert_eq!(payload_reads(&reads), 2);
    }
}
