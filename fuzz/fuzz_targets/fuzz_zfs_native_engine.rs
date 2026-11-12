#![forbid(unsafe_code)]
#![no_main]

//! Bounded hostile-media fuzzer for native ZFS 4-label XDR `NvList` configs,
//! uberblocks, block pointers, gang headers, RAIDZ1/2/3 geometry & parity,
//! LZJB/LZ4/ZSTD/GZIP/ZLE decompressors, DMU/ZAP/ZPL/ZIL, scrub/allocation
//! audits, and `ffs::open_read_only_device` (`bd-2tzok`).

use std::ffi::OsStr;
use std::sync::Arc;

use asupersync::Cx;
use ffs::{
    open_read_only_device, InodeNumber, ReadOnlyBackend, ReadOnlyOpenOptions, RequestScope,
    ZfsReadOptions, ZfsRootSelection,
};
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_fuzz::{
    zfs_baseline, BoundedRoFuzzDevice, ByteCursor, FuzzBacking, FuzzBudgetTracker, FuzzBudgets,
    PatchBuilder,
};
use ffs_ondisk::zfs::gang::GangHeader;
use ffs_ondisk::zfs::nvlist::NvList;
use ffs_ondisk::zfs::raidz::parity::RaidzParityMap;
use ffs_ondisk::zfs::raidz::Raidz1Map;
use ffs_ondisk::zfs::{
    decompress, label_offsets, verify_label_checksum, BlockPointer, Endian, Uberblock, DATA_OFFSET,
    LABEL_BYTES, LABEL_CONFIG_OFFSET, UBERBLOCK_RING_OFFSET,
};
use ffs_ondisk::zfs_dmu::{microzap, Dnode, ObjectSet, ZilBlock, ZilHeader};
use ffs_ondisk::zfs_zap::FatHeader;
use ffs_ondisk::zfs_zpl::{directory_reference, Metadata as ZplMetadata};
use ffs_zfs::reader::dmu::allocation::AllocationLimits;
use ffs_zfs::reader::dmu::scrub::ScrubLimits;
use ffs_zfs::{Leaf, Pool};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4_096;

const ZFS_INTERESTING_OFFSETS: [u64; 12] = [
    LABEL_CONFIG_OFFSET,
    UBERBLOCK_RING_OFFSET,
    LABEL_BYTES + LABEL_CONFIG_OFFSET,
    LABEL_BYTES + UBERBLOCK_RING_OFFSET,
    DATA_OFFSET + 0x0C_000,
    DATA_OFFSET + 0x10_000,
    DATA_OFFSET + 0x14_000,
    DATA_OFFSET + 0x18_000,
    DATA_OFFSET + 0x20_000,
    DATA_OFFSET + 0x25_000,
    DATA_OFFSET + 0x26_000,
    DATA_OFFSET + 0x28_000,
];

fn fuzz_pure_zfs_parsers_and_codecs(data: &[u8], tracker: &FuzzBudgetTracker) {
    let order = if data.first().copied().unwrap_or(0) & 1 == 0 {
        Endian::Little
    } else {
        Endian::Big
    };

    let slice = &data[..data.len().min(1024)];
    let _ = NvList::parse(slice);
    let _ = NvList::parse_exact(slice);

    if data.len() >= 128 {
        if let Ok(bp) = BlockPointer::parse(&data[..128], order) {
            let _ = bp.regular_dvas();
            let _ = bp.decode_embedded();
            if data.len() >= 640 {
                let _ = GangHeader::parse(&data[128..640], &bp, &[512, 512, 512]);
            }
            if bp.physical_bytes() <= data.len().saturating_sub(128) && bp.logical_bytes() <= 8192 {
                if let Ok(decoded) = bp.decode(&data[128..128 + bp.physical_bytes()]) {
                    let _ = tracker.charge_decoded(decoded.len());
                }
            }
        }
    }

    if data.len() >= 1024 {
        let _ = verify_label_checksum(&data[..1024], UBERBLOCK_RING_OFFSET);
        let _ = Uberblock::parse(&data[..1024], UBERBLOCK_RING_OFFSET);
        let _ = ObjectSet::parse(&data[..1024], order);
    }

    if data.len() >= 512 {
        let _ = Dnode::parse(&data[..512], order);
        let _ = microzap(&data[..512], order);
        let _ = FatHeader::parse(&data[..512], order, 64);
        let _ = ZilHeader::parse(&data[..512], order);
        let _ = ZilBlock::parse(&data[..512], order);
    }
    if data.len() >= 264 {
        let _ = ZplMetadata::legacy(&data[..264], order);
    }
    if data.len() >= 8 {
        let raw_ref = u64::from_le_bytes(data[..8].try_into().unwrap());
        let _ = directory_reference(raw_ref);
    }

    // RAIDZ1 / RAIDZ2 / RAIDZ3 mapping & reconstruction bounds
    if let Ok(map1) = Raidz1Map::new(0, 1024, 9, 3) {
        let c0 = [0xAA_u8; 512];
        let c1 = &data[..data.len().min(512)];
        if c1.len() == 512 {
            let _ = map1.assemble(&[Some(&c0), Some(c1), None], Some(2));
        }
    }
    if let Ok(map2) = RaidzParityMap::new(0, 1024, 9, 4, 2) {
        let _ = map2.columns();
    }

    // Bounded ZFS decompression codecs (uncompressed=2, LZJB=3, GZIP=5..13, ZLE=14, LZ4=15, ZSTD=16)
    for codec in [2_u8, 3, 6, 14, 15, 16] {
        if let Ok(out) = decompress(slice, codec, 4096) {
            assert_eq!(out.len(), 4096);
            let _ = tracker.charge_decoded(out.len());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let mut cursor = ByteCursor::new(data);
    let mode = cursor.next_u8() % 6;
    let replay_zil = cursor.next_bool();
    let use_snapshot = !replay_zil && cursor.next_u8().is_multiple_of(4);
    let cancel_after_ops = if cursor.next_u8().is_multiple_of(8) {
        Some(1 + usize::from(cursor.next_u8() % 24))
    } else {
        None
    };

    let tracker = FuzzBudgetTracker::new(FuzzBudgets {
        max_physical_read_bytes: 8 * 1024 * 1024,
        max_decoded_bytes: 1024 * 1024,
        max_retained_bytes: 1024 * 1024,
        max_depth: 8,
        max_ops: 768,
        max_replica_attempts: 64,
    });

    fuzz_pure_zfs_parsers_and_codecs(data, &tracker);

    let mut expect_file_checksum_err = false;
    let backing = match mode {
        0 => {
            let mut raw = cursor.remainder().to_vec();
            if raw.len() < 4096 {
                raw.resize(4096, 0);
            }
            FuzzBacking::from_owned(raw)
        }
        1 => {
            let (base, digest) = zfs_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.apply_interesting_mutations(&mut cursor, &ZFS_INTERESTING_OFFSETS, 10);
            pb.finish()
        }
        2 => {
            // Planted final-byte corruption in ZPL `/hello.txt` data block (`DATA_OFFSET + 0x28_000`)
            expect_file_checksum_err = true;
            let (base, digest) = zfs_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.xor_byte(DATA_OFFSET + 0x28_000 + 511, 0x01);
            pb.finish()
        }
        3 => {
            // Corrupt label 0 & label 1 uberblocks while keeping label 2 & 3 intact (replica fallback)
            let (base, digest) = zfs_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            if let Ok(offsets) = label_offsets(base.len() as u64) {
                pb.xor_byte(offsets[0] + UBERBLOCK_RING_OFFSET, 0xFF);
                pb.xor_byte(offsets[1] + UBERBLOCK_RING_OFFSET, 0xFF);
            }
            pb.finish()
        }
        4 => {
            // Corrupt ALL 4 label configs -> must fail closed (`Err`)
            let (base, digest) = zfs_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            if let Ok(offsets) = label_offsets(base.len() as u64) {
                for off in offsets {
                    pb.xor_byte(off + LABEL_CONFIG_OFFSET + 8, 0xFF);
                }
            }
            pb.finish()
        }
        _ => {
            // Corrupt root directory MicroZAP block -> directory list/lookup fails closed
            let (base, digest) = zfs_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.xor_byte(DATA_OFFSET + 0x26_000 + 64, 0x55);
            pb.finish()
        }
    };

    let backing_clone = backing.clone();
    let dev = BoundedRoFuzzDevice::new(backing, Arc::clone(&tracker), cancel_after_ops);
    let cx = Cx::for_testing();

    if let Ok(leaf) = Leaf::from_device(
        &cx,
        Box::new(Arc::clone(&dev) as Arc<dyn ByteDevice>),
        0,
        dev.len_bytes(),
    ) {
        if let Ok(lbl0) = leaf.label(&cx, 0) {
            let _ = leaf.uberblock(&cx, &lbl0, 0);
        }
        if let Ok(pool) = Pool::from_leaves(vec![leaf]) {
            if let Ok(mut objects) = pool.import_objects(&cx, None) {
                if let Ok(datasets) = objects.datasets(&cx) {
                    let _ = tracker.charge_retained(datasets.len().saturating_mul(128));
                }
                let _ = objects.zap(&cx, 1);
                let _ = objects.intent_log(&cx, &[]);
                let _ = objects.allocation(
                    &cx,
                    AllocationLimits {
                        metaslabs: 16,
                        records: 512,
                        metadata_bytes: 512 * 1024,
                        ranges_per_metaslab: 256,
                    },
                );
                let _ = objects.scrub(
                    &cx,
                    ScrubLimits {
                        pointers: 512,
                        decoded_bytes: 512 * 1024,
                        objects: 256,
                        copy_bytes: Some(512 * 1024),
                    },
                );
                if let Ok(mut zpl) = objects.zpl(&cx, &[]) {
                    if replay_zil {
                        let _ = zpl.replay_zil(&cx);
                    }
                    let _ = zpl.snapshots(&cx);
                    let _ = zpl.stat(&cx, 2);
                    let _ = zpl.list(&cx, 2);
                    let _ = zpl.listxattr(&cx, 2);
                    if let Ok(bytes) = zpl.read(&cx, 3, 0, 512) {
                        let _ = tracker.charge_decoded(bytes.len());
                    }
                }
            }
        }
    }
    dev.assert_invariants();

    let facade_cx = Cx::for_testing();
    let facade_dev = BoundedRoFuzzDevice::new(
        backing_clone,
        FuzzBudgetTracker::new(FuzzBudgets::default()),
        None,
    );
    let root_sel = match cursor.next_u8() % 3 {
        0 => ZfsRootSelection::Auto,
        1 => ZfsRootSelection::Pool(424_242),
        _ => ZfsRootSelection::Candidate {
            pool_guid: 424_242,
            label: 0,
            slot: 0,
        },
    };
    let zfs_opts = ZfsReadOptions {
        additional_images: Vec::new(),
        root: root_sel,
        dataset: if cursor.next_u8().is_multiple_of(4) {
            vec![b"app".to_vec()]
        } else {
            Vec::new()
        },
        snapshot: if use_snapshot {
            Some(b"snap1".to_vec())
        } else {
            None
        },
        replay_zil,
        missing: ffs::ZfsMissingMembers::None,
    };
    if let Ok(opened) = open_read_only_device(
        &facade_cx,
        Arc::clone(&facade_dev) as Arc<dyn ByteDevice>,
        &ReadOnlyOpenOptions {
            backend: ReadOnlyBackend::Zfs(zfs_opts),
            ..ReadOnlyOpenOptions::default()
        },
    ) {
        assert_ne!(
            mode, 4,
            "corrupting all four ZFS vdev labels must never admit a pool"
        );
        let mut scope = RequestScope::empty();
        let _ = opened
            .filesystem
            .statfs(&facade_cx, &mut scope, InodeNumber(1));
        let _ = opened
            .filesystem
            .readdir(&facade_cx, &mut scope, InodeNumber(1), 0);
        if let Ok(hello) = opened.filesystem.lookup(
            &facade_cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("hello.txt"),
        ) {
            let res = opened
                .filesystem
                .read(&facade_cx, &mut scope, hello.ino, 0, 512);
            if expect_file_checksum_err {
                assert!(
                    res.is_err(),
                    "planted ZFS final-byte checksum corruption must fail closed"
                );
            }
            assert!(matches!(
                opened
                    .filesystem
                    .write(&facade_cx, &mut scope, hello.ino, 0, b"nope"),
                Err(FfsError::ReadOnly)
            ));
        }
    }
    facade_dev.assert_invariants();
});
