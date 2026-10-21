//! Full constructed labels -> MOS -> DSL -> ZPL -> extraction mount coverage.
//! This does not claim native OpenZFS or kernel FUSE interchange.

use super::*;
use crate::filesystem::ZfsFs;
use crate::reader::Pool;
use crate::reader::tests::mirror::{Fault, MIRROR_GUID, install_labels, native_config, open_bytes};
use ffs_core::{FsOps, RequestScope};
use ffs_types::InodeNumber;
use std::ffi::OsStr;

const POOL_ROOT: u64 = DATA_OFFSET + 0x34000;

fn mirror_graph(
    order: Endian,
    sa: u8,
    case: u8,
    reads: &[Reads; 2],
    damaged: [&[u64]; 2],
    faults: [Fault; 2],
) -> Pool {
    let cx = Cx::for_testing();
    let (source, _) = graph(order, sa, case, Arc::default(), None);
    let mut bytes = vec![0xa5; BASE + LENGTH + 512];
    bytes[BASE..BASE + LENGTH].copy_from_slice(&source.read(&cx, 0, LENGTH).unwrap());
    bytes[BASE + LENGTH..].fill(0x5a);
    let table = source.read(&cx, MOS, 16384).unwrap();
    let mut meta = node(10, 16384, 1, 0, &[], 0, order);
    meta[64..192].copy_from_slice(&bp(&table, MOS, 10, 0, 50, order, order));
    let mut root = vec![0; 1024];
    root[..512].copy_from_slice(&meta);
    root[704..712].copy_from_slice(&order.encode(1));
    bytes[BASE + POOL_ROOT as usize..BASE + POOL_ROOT as usize + root.len()].copy_from_slice(&root);
    let guids = [1001, 1002];
    let mut uberblock = vec![0; 1024];
    for (at, value) in [
        (0, 0x00ba_b10c),
        (8, 5000),
        (16, 61),
        (24, 123 + MIRROR_GUID + guids[0] + guids[1]),
        (32, 1_700_000_000),
    ] {
        uberblock[at..at + 8].copy_from_slice(&order.encode(value));
    }
    uberblock[40..168].copy_from_slice(&bp(&root, POOL_ROOT, 11, 0, 60, order, order));
    let mut leaves = Vec::new();
    for index in 0..2 {
        let mut image = bytes.clone();
        let config = native_config(
            guids[index],
            &guids,
            9,
            LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES,
            60,
        );
        install_labels(&mut image, BASE, LENGTH as u64, order, &config, &uberblock);
        for offset in damaged[index] {
            image[BASE + *offset as usize] ^= 1;
        }
        leaves.push(open_bytes(
            image,
            BASE,
            LENGTH as u64,
            Arc::clone(&reads[index]),
            faults[index],
        ));
    }
    Pool::from_leaves(leaves).unwrap()
}

fn count(reads: &Reads, offset: u64) -> usize {
    reads
        .lock()
        .unwrap()
        .iter()
        .filter(|(at, _)| *at == BASE as u64 + offset)
        .count()
}

#[test]
fn mirror_mount_reads_legacy_sa_spill_and_embedded_files_through_verified_alternatives() {
    let cx = Cx::for_testing();
    for order in [Endian::Little, Endian::Big] {
        for sa in 0..=2 {
            for case in [0, 9] {
                let reads: [Reads; 2] = std::array::from_fn(|_| Arc::default());
                let view = {
                    let pool = mirror_graph(
                        order,
                        sa,
                        case,
                        &reads,
                        [
                            &[POOL_ROOT, TABLE, ROOT_MAP, INDIRECT, FIRST, SPILL],
                            &[LAST],
                        ],
                        [Fault::None; 2],
                    );
                    let mut objects = pool.objects(&cx, 0, 2, 123).unwrap();
                    objects.zpl(&cx, &[]).unwrap()
                };
                let fs = ZfsFs::new(&cx, view, 1000, 1000).unwrap();
                let mut scope = RequestScope::empty();
                let root = InodeNumber(1);
                let file = fs
                    .lookup(&cx, &mut scope, root, OsStr::new("file.bin"))
                    .unwrap();
                let alias = fs
                    .lookup(&cx, &mut scope, root, OsStr::new("alias.bin"))
                    .unwrap();
                assert_eq!(file.ino, alias.ino);
                let mut expected = vec![b'A'; 512];
                expected.extend_from_slice(&[0; 512]);
                expected.extend_from_slice(b"BBB");
                assert_eq!(
                    fs.read(&cx, &mut scope, file.ino, 0, 4096).unwrap(),
                    expected
                );
                let counts = [
                    reads[0].lock().unwrap().len(),
                    reads[1].lock().unwrap().len(),
                ];
                assert_eq!(
                    fs.read(&cx, &mut scope, alias.ino, 510, 600).unwrap(),
                    expected[510..]
                );
                assert_eq!(
                    fs.read(&cx, &mut scope, file.ino, 1027, 1).unwrap(),
                    [] as [u8; 0]
                );
                assert_eq!(
                    [
                        reads[0].lock().unwrap().len(),
                        reads[1].lock().unwrap().len()
                    ],
                    counts
                );
                for offset in [POOL_ROOT, TABLE, ROOT_MAP, INDIRECT] {
                    assert!(count(&reads[0], offset) > 0);
                    assert!(count(&reads[1], offset) > 0);
                }
                if sa == 2 {
                    assert!(count(&reads[0], SPILL) > 0);
                    assert!(count(&reads[1], SPILL) > 0);
                }
                if case == 0 {
                    assert_eq!(count(&reads[0], FIRST), 1);
                    assert_eq!(count(&reads[1], FIRST), 1);
                    assert_eq!(count(&reads[0], LAST), 1);
                    assert_eq!(count(&reads[1], LAST), 0);
                } else {
                    for reads in &reads {
                        assert_eq!(count(reads, FIRST), 0);
                        assert_eq!(count(reads, LAST), 0);
                    }
                }
                for reads in &reads {
                    assert!(reads.lock().unwrap().iter().all(|(offset, size)| {
                        *offset >= BASE as u64 && *offset + *size as u64 <= (BASE + LENGTH) as u64
                    }));
                }
            }
        }
    }
}

#[test]
fn failed_or_cancelled_mirror_file_blocks_never_enter_the_dataset_cache() {
    let cx = Cx::for_testing();
    for case in 0..3 {
        let reads: [Reads; 2] = std::array::from_fn(|_| Arc::default());
        let at = BASE as u64 + FIRST;
        let faults = match case {
            1 => [Fault::Cancel(at), Fault::None],
            2 => [Fault::Io(at), Fault::Cancel(at)],
            _ => [Fault::None; 2],
        };
        let damage: [&[u64]; 2] = if case == 0 {
            [&[FIRST], &[FIRST]]
        } else {
            [&[], &[]]
        };
        let pool = mirror_graph(Endian::Little, 2, 0, &reads, damage, faults);
        let mut objects = pool.objects(&cx, 0, 2, 123).unwrap();
        let mut view = objects.zpl(&cx, &[]).unwrap();
        let result = view.read(&cx, 3, 0, 1027);
        if case == 0 {
            assert!(result.is_err());
        } else {
            assert!(matches!(result, Err(FfsError::Cancelled)));
        }
        assert!(
            view.objects
                .cache
                .iter()
                .all(|(bp, _)| bp.object_type() != 19 || bp.level() != 0)
        );
        // Verified metadata can remain cached; no file-data success was seen.
        assert!(!view.objects.cache.is_empty());
        assert_eq!(count(&reads[0], FIRST), 1);
        assert_eq!(count(&reads[1], FIRST), usize::from(case != 1));
        assert_eq!(count(&reads[0], LAST), 0);
        assert_eq!(count(&reads[1], LAST), 0);
        assert_eq!(view.stat(&cx, 3).unwrap().0.size, 1027);
    }
}
