#![forbid(unsafe_code)]
#![no_main]

//! Bounded hostile-media fuzzer for MBR + GPT partition discovery, backup-GPT
//! CRC fallback rules, overlapping/out-of-bounds/nested-partition-bomb
//! rejection, `PartitionByteDevice` slice clamping, and partitioned
//! `ffs::open_read_only_device` (`bd-2tzok`).

use std::str::FromStr;
use std::sync::Arc;

use asupersync::Cx;
use ffs::{
    discover_partitions_on_device, open_read_only_device, select_partition_device, InodeNumber,
    PartUuid, PartitionParseOptions, PartitionSelector, ReadOnlyOpenOptions, RequestScope,
};
use ffs_block::io_engine::VolumeAccess;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_fuzz::{
    gpt_multi_format_baseline, mbr_multi_format_baseline, BoundedRoFuzzDevice, ByteCursor,
    FuzzBacking, FuzzBudgetTracker, FuzzBudgets, PatchBuilder,
};
use ffs_types::ByteOffset;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4_096;

const PARTITION_INTERESTING_OFFSETS: [u64; 10] = [
    0,
    446,
    462,
    510,
    512,
    512 + 16,
    512 + 24,
    512 + 72,
    2 * 512,
    2 * 512 + 128,
];

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let mut cursor = ByteCursor::new(data);
    let mode = cursor.next_u8() % 7;
    let allow_backup_gpt = cursor.next_bool();
    let cancel_after_ops = if cursor.next_u8().is_multiple_of(8) {
        Some(1 + usize::from(cursor.next_u8() % 16))
    } else {
        None
    };

    if let Ok(sel_str) = std::str::from_utf8(&data[..data.len().min(64)]) {
        let _ = PartitionSelector::from_str(sel_str);
        let _ = PartUuid::from_str(sel_str);
    }

    let mut must_reject_partition_1 = false;
    let mut must_reject_table = false;
    let backing = match mode {
        0 => {
            let mut raw = cursor.remainder().to_vec();
            if raw.len() < 2048 {
                raw.resize(2048, 0);
            }
            FuzzBacking::from_owned(raw)
        }
        1 => {
            let (base, digest) = gpt_multi_format_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.apply_interesting_mutations(&mut cursor, &PARTITION_INTERESTING_OFFSETS, 10);
            pb.finish()
        }
        2 => {
            let (base, digest) = mbr_multi_format_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.apply_interesting_mutations(&mut cursor, &PARTITION_INTERESTING_OFFSETS[..4], 8);
            pb.finish()
        }
        3 => {
            // Corrupt primary GPT header magic/CRC; must reject when allow_backup_gpt == false!
            if !allow_backup_gpt {
                must_reject_table = true;
            }
            let (base, digest) = gpt_multi_format_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.xor_byte(512 + 16, 0xFF);
            pb.finish()
        }
        4 => {
            // Planted nested GPT-inside-GPT partition bomb inside Partition #1 (LBA 64)
            must_reject_partition_1 = true;
            let (base, digest) = gpt_multi_format_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.write(64 * 512, &base[..2 * 512]);
            pb.finish()
        }
        5 => {
            // Planted overlapping MBR partitions (Entry 2 overlaps Entry 1 at LBA 8)
            must_reject_table = true;
            let (base, digest) = mbr_multi_format_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.write(462 + 8, &8_u32.to_le_bytes());
            pb.finish()
        }
        _ => {
            // Truncated GPT disk cutting off backup GPT + tail of Partition 2
            must_reject_table = true;
            let (base, digest) = gpt_multi_format_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.truncate(1200 * 512);
            pb.finish()
        }
    };

    let backing_clone = backing.clone();
    let tracker = FuzzBudgetTracker::new(FuzzBudgets {
        max_physical_read_bytes: 4 * 1024 * 1024,
        max_decoded_bytes: 512 * 1024,
        max_retained_bytes: 512 * 1024,
        max_depth: 4,
        max_ops: 512,
        max_replica_attempts: 32,
    });
    let dev = BoundedRoFuzzDevice::new(backing, Arc::clone(&tracker), cancel_after_ops);
    let cx = Cx::for_testing();
    let parse_opts = PartitionParseOptions {
        allow_backup_gpt_fallback: allow_backup_gpt,
        ..PartitionParseOptions::default()
    };

    let table_res = discover_partitions_on_device(&cx, dev.as_ref(), &parse_opts);
    if must_reject_table && cancel_after_ops.is_none() {
        assert!(
            table_res.is_err(),
            "planted corrupt/overlapping/truncated partition table must fail closed"
        );
    }

    if let Ok(table) = table_res {
        let _ = tracker.charge_retained(table.partitions.len().saturating_mul(128));
        // Verify pairwise disjointness and backing bounds on every admitted table!
        for (i, a) in table.partitions.iter().enumerate() {
            assert!(a.byte_len > 0);
            assert!(a.end_byte() <= dev.len_bytes());
            for b in &table.partitions[i + 1..] {
                assert!(
                    a.end_lba_inclusive < b.start_lba || b.end_lba_inclusive < a.start_lba,
                    "admitted partition table must never contain overlapping LBA ranges"
                );
            }
        }
    }

    let selector = match cursor.next_u8() % 4 {
        0 => PartitionSelector::Index(1),
        1 => PartitionSelector::Index(2),
        2 => PartitionSelector::Label("FAT16_DATA".to_owned()),
        _ => PartitionSelector::PartUuid(
            PartUuid::from_str("cccccccc-0000-4000-8000-000000000001").unwrap(),
        ),
    };

    if let Ok((_table, part_dev)) = select_partition_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        &selector,
        &parse_opts,
        VolumeAccess::ReadOnly,
    ) {
        if part_dev.entry().index == 1 && must_reject_partition_1 {
            panic!("nested GPT partition bomb inside Partition #1 must never be selected");
        }
        // Out-of-bounds read at partition_len must always be rejected!
        let mut oob = [0_u8; 1];
        assert!(
            part_dev
                .read_exact_at(&cx, ByteOffset(part_dev.len_bytes()), &mut oob)
                .is_err(),
            "PartitionByteDevice must reject reads at or beyond partition byte_len"
        );
    }
    dev.assert_invariants();

    let facade_cx = Cx::for_testing();
    let facade_dev = BoundedRoFuzzDevice::new(
        backing_clone,
        FuzzBudgetTracker::new(FuzzBudgets::default()),
        None,
    );
    let open_res = open_read_only_device(
        &facade_cx,
        Arc::clone(&facade_dev) as Arc<dyn ByteDevice>,
        &ReadOnlyOpenOptions {
            partition: Some(selector.clone()),
            allow_backup_gpt,
            ..ReadOnlyOpenOptions::default()
        },
    );
    if must_reject_table
        || (must_reject_partition_1
            && matches!(
                selector,
                PartitionSelector::Index(1) | PartitionSelector::PartUuid(_)
            ))
    {
        assert!(
            open_res.is_err(),
            "open_read_only_device must fail closed on invalid partition table or nested bomb"
        );
    }
    if let Ok(opened) = open_res {
        let mut scope = RequestScope::empty();
        let _ = opened
            .filesystem
            .statfs(&facade_cx, &mut scope, InodeNumber(1));
        let _ = opened
            .filesystem
            .getattr(&facade_cx, &mut scope, InodeNumber(1));
        let _ = opened
            .filesystem
            .readdir(&facade_cx, &mut scope, InodeNumber(1), 0);
        assert!(matches!(
            opened
                .filesystem
                .write(&facade_cx, &mut scope, InodeNumber(1), 0, b"nope"),
            Err(FfsError::ReadOnly)
        ));
    }
    facade_dev.assert_invariants();
});
