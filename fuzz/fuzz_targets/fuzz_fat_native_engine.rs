#![forbid(unsafe_code)]
#![no_main]

//! Bounded hostile-media fuzzer for native FAT16/FAT32 geometry, LFN/OEM
//! directory decoding, cluster-chain cycle/truncation rejection, `FatVolume`
//! checks, and `ffs::open_read_only_device` (`bd-2tzok`).

use std::ffi::OsStr;
use std::sync::Arc;

use asupersync::Cx;
use ffs::{open_read_only_device, InodeNumber, ReadOnlyBackend, ReadOnlyOpenOptions, RequestScope};
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_fat::{Directory, EntrySlots, FatVolume};
use ffs_fuzz::{
    fat16_baseline, fat32_baseline, BoundedRoFuzzDevice, ByteCursor, FuzzBacking,
    FuzzBudgetTracker, FuzzBudgets, PatchBuilder,
};
use ffs_ondisk::fat::{
    short_name_checksum, FatDirectoryDecoder, FatGeometry, FatKind, FatOemCodePage,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4_096;

const FAT16_INTERESTING_OFFSETS: [u64; 10] = [
    0,
    11,
    13,
    17,
    19,
    21,
    22,
    512,
    (1 + 17) * 512,
    (1 + 34) * 512,
];

const FAT32_INTERESTING_OFFSETS: [u64; 10] = [0, 32, 36, 40, 44, 48, 50, 512, 6 * 512, 32 * 512];

fn fuzz_pure_fat_parsers(data: &[u8], tracker: &FuzzBudgetTracker) {
    if data.len() >= 512 {
        let backing_hint = (data.len() as u64).saturating_mul(64);
        let _ = FatGeometry::parse(&data[..512], backing_hint);
    }

    let kind = if data.first().copied().unwrap_or(0) & 1 == 0 {
        FatKind::Fat16
    } else {
        FatKind::Fat32
    };
    let mut decoder = FatDirectoryDecoder::default();
    for slot in data.as_chunks::<32>().0.iter().take(64) {
        if tracker.charge_op().is_err() {
            break;
        }
        if let Ok(Some(entry)) = decoder.push(slot, kind) {
            let _ = tracker.charge_decoded(32);
            let _ = entry.ascii_short_name();
            let _ = entry.oem_short_name(FatOemCodePage::Cp437);
            let _ = entry.oem_short_name(FatOemCodePage::Cp850);
            let _ = entry.created_timestamp();
            let _ = entry.accessed_timestamp();
            let _ = entry.modified_timestamp();
        }
    }
    decoder.finish();

    if data.len() >= 11 {
        let mut short = [0_u8; 11];
        short.copy_from_slice(&data[..11]);
        let _ = short_name_checksum(&short);
    }

    if let Ok(text) = std::str::from_utf8(&data[..data.len().min(96)]) {
        let _ = EntrySlots::parse(text);
    }
}

fn walk_fat_directory_bounded(
    cx: &Cx,
    vol: &FatVolume,
    dir: Directory,
    depth: usize,
    tracker: &FuzzBudgetTracker,
) {
    if tracker.check_depth(depth).is_err() || tracker.charge_op().is_err() {
        return;
    }
    let Ok(entries) = vol.list(cx, dir) else {
        return;
    };
    if tracker
        .charge_retained(entries.len().saturating_mul(128))
        .is_err()
    {
        return;
    }
    for entry in entries.into_iter().take(12) {
        let _ = entry.name();
        let _ = entry.short_alias();
        if entry.native.is_directory() {
            if let Ok(child_dir) = entry.directory() {
                walk_fat_directory_bounded(cx, vol, child_dir, depth + 1, tracker);
            }
        } else {
            if let Ok(chain) = vol.file_chain(cx, &entry) {
                if let Ok(bytes) = vol.read(cx, &chain, 0, 1024) {
                    let _ = tracker.charge_decoded(bytes.len());
                }
            }
            if let Ok(mut reader) = vol.open_file_reader(cx, &entry) {
                let tail_off = reader.len_bytes().saturating_sub(64);
                if let Ok(bytes) = reader.read(cx, tail_off, 128) {
                    let _ = tracker.charge_decoded(bytes.len());
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let mut cursor = ByteCursor::new(data);
    let mode = cursor.next_u8() % 7;
    let code_page = match cursor.next_u8() % 3 {
        0 => FatOemCodePage::Ascii,
        1 => FatOemCodePage::Cp437,
        _ => FatOemCodePage::Cp850,
    };
    let cancel_after_ops = if cursor.next_u8().is_multiple_of(8) {
        Some(1 + usize::from(cursor.next_u8() % 24))
    } else {
        None
    };

    let tracker = FuzzBudgetTracker::new(FuzzBudgets {
        max_physical_read_bytes: 4 * 1024 * 1024,
        max_decoded_bytes: 512 * 1024,
        max_retained_bytes: 512 * 1024,
        max_depth: 6,
        max_ops: 640,
        max_replica_attempts: 48,
    });

    fuzz_pure_fat_parsers(data, &tracker);

    let mut expect_cycle_or_truncation_err = false;
    let backing = match mode {
        0 => {
            // Raw fuzzer bytes padded to sector boundary
            let mut raw = cursor.remainder().to_vec();
            if raw.len() < 1024 {
                raw.resize(1024, 0);
            }
            FuzzBacking::from_owned(raw)
        }
        1 | 2 => {
            let (base, digest) = if mode == 1 {
                fat16_baseline()
            } else {
                fat32_baseline()
            };
            let mut pb = PatchBuilder::from_static(base, digest);
            let offsets = if mode == 1 {
                &FAT16_INTERESTING_OFFSETS[..]
            } else {
                &FAT32_INTERESTING_OFFSETS[..]
            };
            pb.apply_interesting_mutations(&mut cursor, offsets, 12);
            pb.finish()
        }
        3 => {
            // Planted cluster-chain cycle on FAT16 (`3 -> 4 -> 3`)
            expect_cycle_or_truncation_err = true;
            let (base, digest) = fat16_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            for copy in 0..2_u64 {
                pb.write((1 + copy * 17) * 512 + 4 * 2, &3_u16.to_le_bytes());
            }
            pb.finish()
        }
        4 => {
            // Planted final-cluster truncation (`3 -> EOC` even though file size = 700 > 512)
            expect_cycle_or_truncation_err = true;
            let (base, digest) = fat16_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            for copy in 0..2_u64 {
                pb.write((1 + copy * 17) * 512 + 3 * 2, &0xFFFF_u16.to_le_bytes());
            }
            pb.finish()
        }
        5 => {
            // Planted FAT copy disagreement (`FAT #0 != FAT #1` at cluster 3)
            expect_cycle_or_truncation_err = true;
            let (base, digest) = fat16_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.write(512 + 3 * 2, &6_u16.to_le_bytes());
            pb.finish()
        }
        _ => {
            // Truncated volume backing before final cluster
            expect_cycle_or_truncation_err = true;
            let (base, digest) = fat16_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            let cut = 39 * 512 + u64::from(cursor.next_u16() % 1024);
            pb.truncate(cut);
            pb.finish()
        }
    };

    let dev = BoundedRoFuzzDevice::new(backing, Arc::clone(&tracker), cancel_after_ops);
    let cx = Cx::for_testing();

    if let Ok(vol) = FatVolume::from_device(
        &cx,
        Box::new(Arc::clone(&dev) as Arc<dyn ByteDevice>),
        0,
        dev.len_bytes(),
    ) {
        let vol = vol.with_oem_code_page(code_page);
        walk_fat_directory_bounded(&cx, &vol, Directory::Root, 0, &tracker);
        let _ = vol.lookup(&cx, Directory::Root, "Native payload.bin");
        let _ = vol.resolve(&cx, "/SUBDIR/nested.txt");
        if mode != 2 {
            // Full cluster scan on compact FAT16 / raw images
            let _ = vol.free_clusters(&cx);
            let _ = vol.check(&cx);
        }
    }

    let facade_cx = Cx::for_testing();
    let facade_tracker = FuzzBudgetTracker::new(FuzzBudgets {
        max_physical_read_bytes: 4 * 1024 * 1024,
        max_decoded_bytes: 512 * 1024,
        max_retained_bytes: 512 * 1024,
        max_depth: 6,
        max_ops: 640,
        max_replica_attempts: 48,
    });
    // Re-wrap the same immutable virtual image for public facade verification
    let mut probe_buf = vec![0_u8; dev.len_bytes().min(4096) as usize];
    let _ = dev.read_exact_at(&Cx::for_testing(), ffs_types::ByteOffset(0), &mut probe_buf);
    dev.assert_invariants();

    if mode != 0 {
        let (base, digest) = if mode == 2 {
            fat32_baseline()
        } else {
            fat16_baseline()
        };
        let mut pb = PatchBuilder::from_static(base, digest);
        if mode == 3 {
            for copy in 0..2_u64 {
                pb.write((1 + copy * 17) * 512 + 4 * 2, &3_u16.to_le_bytes());
            }
        } else if mode == 4 {
            for copy in 0..2_u64 {
                pb.write((1 + copy * 17) * 512 + 3 * 2, &0xFFFF_u16.to_le_bytes());
            }
        } else if mode == 5 {
            pb.write(512 + 3 * 2, &6_u16.to_le_bytes());
        } else if mode == 6 {
            pb.truncate(40 * 512);
        }
        let facade_dev = BoundedRoFuzzDevice::new(pb.finish(), facade_tracker, None);
        if let Ok(opened) = open_read_only_device(
            &facade_cx,
            Arc::clone(&facade_dev) as Arc<dyn ByteDevice>,
            &ReadOnlyOpenOptions {
                backend: ReadOnlyBackend::Fat {
                    oem_code_page: code_page,
                },
                ..ReadOnlyOpenOptions::default()
            },
        ) {
            let mut scope = RequestScope::empty();
            let _ = opened
                .filesystem
                .statfs(&facade_cx, &mut scope, InodeNumber(1));
            let _ = opened
                .filesystem
                .readdir(&facade_cx, &mut scope, InodeNumber(1), 0);
            let lookup_or_read = opened
                .filesystem
                .lookup(
                    &facade_cx,
                    &mut scope,
                    InodeNumber(1),
                    OsStr::new("Native payload.bin"),
                )
                .and_then(|file| {
                    assert!(matches!(
                        opened
                            .filesystem
                            .write(&facade_cx, &mut scope, file.ino, 0, b"nope"),
                        Err(FfsError::ReadOnly)
                    ));
                    opened
                        .filesystem
                        .read(&facade_cx, &mut scope, file.ino, 0, 1024)
                });
            if expect_cycle_or_truncation_err {
                assert!(
                    lookup_or_read.is_err(),
                    "planted FAT cycle/truncation/disagreement must never return partial bytes"
                );
            }
        }
        facade_dev.assert_invariants();
    }
});
