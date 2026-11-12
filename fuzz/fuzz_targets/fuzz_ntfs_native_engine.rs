#![forbid(unsafe_code)]
#![no_main]

//! Bounded hostile-media fuzzer for native NTFS MFT USA fixups, ATTRIBUTE_LIST,
//! mapping-pair runlists, `$I30` B-tree lookup, `$LogFile` recovery planning,
//! LZNT1 / WOF XPRESS / LZX decompressors, `$Secure` descriptors, ownership
//! accounting, and `ffs::open_read_only_device` (`bd-2tzok`).

use std::ffi::OsStr;
use std::sync::Arc;

use asupersync::Cx;
use ffs::{open_read_only_device, InodeNumber, ReadOnlyBackend, ReadOnlyOpenOptions, RequestScope};
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_fuzz::{
    ntfs_baseline, BoundedRoFuzzDevice, ByteCursor, FuzzBacking, FuzzBudgetTracker, FuzzBudgets,
    PatchBuilder,
};
use ffs_ntfs::reader::allocation::{AllocationLimits, NamespaceLimits, RecordOwnershipLimits};
use ffs_ntfs::reader::security::SecurityCheckLimits;
use ffs_ntfs::{
    NtfsTransactionEngine, NtfsTxOutcome, NtfsVolume, NtfsWriteOptions, StreamName,
};
use ffs_ondisk::ntfs::attribute_list::parse_attribute_list;
use ffs_ondisk::ntfs::ea::{parse_extended_attributes, NtfsEaInformation};
use ffs_ondisk::ntfs::index::parse_index_block;
use ffs_ondisk::ntfs::logfile_writer::{
    encode_client_update_payload, encode_open_attribute_entry, encode_restart_table,
    NtfsClientUpdateSpec, NtfsLogRingWriter, LFS_RECORD_CLIENT,
};
use ffs_ondisk::ntfs::reparse::NtfsReparsePoint;
use ffs_ondisk::ntfs::{
    decode_mapping_pairs, parse_ntfs_logfile, restore_record, NtfsFileRecord, NtfsGeometry,
    NtfsLogOp,
};
use ffs_ondisk::ntfs_security::{
    parse_security_index_block, NtfsSecurityDescriptor, NtfsSecurityHeader,
};
use ffs_ondisk::{lznt1, lzx, xpress};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4_096;

const NTFS_INTERESTING_OFFSETS: [u64; 12] = [
    0,
    40,
    48,
    56,
    64,
    4 * 512,
    4 * 512 + 1024,
    4 * 512 + 3 * 1024,
    4 * 512 + 5 * 1024,
    4 * 512 + 6 * 1024,
    4 * 512 + 24 * 1024,
    128 * 512,
];

fn fuzz_pure_ntfs_parsers_and_codecs(data: &[u8], tracker: &FuzzBudgetTracker) {
    if data.len() >= 512 {
        let _ = NtfsGeometry::parse(&data[..512], (data.len() as u64).saturating_mul(32));
        let _ = restore_record(&data[..data.len().min(1024)], b"FILE");
        let _ = NtfsFileRecord::parse(&data[..data.len().min(1024)]);
    }
    if data.len() >= 4096 {
        let _ = parse_index_block(&data[..4096], 0);
        let _ = parse_ntfs_logfile(&data[..4096]);
        let _ = parse_security_index_block(&data[..4096], 0);
    }

    let slice = &data[..data.len().min(512)];
    let _ = decode_mapping_pairs(slice, 0, 15, 4096);
    let _ = parse_attribute_list(slice);
    let _ = NtfsReparsePoint::parse(slice);
    if slice.len() >= 8 {
        if let Ok(ea_info) = NtfsEaInformation::parse(&slice[..8]) {
            let _ = parse_extended_attributes(&ea_info, &slice[8..]);
        }
    }
    let _ = NtfsSecurityDescriptor::parse(slice);
    let _ = NtfsSecurityHeader::parse(slice);
    if let Ok(text) = std::str::from_utf8(&slice[..slice.len().min(64)]) {
        let _ = StreamName::parse(text);
    }

    // Bounded decompression transforms: output size is strictly capped and exact-length verified.
    if let Ok(decoded) = lznt1::decompress_unit(slice, 4096) {
        assert!(decoded.len() <= 4096);
        let _ = tracker.charge_decoded(decoded.len());
    }
    if let Ok(decoded) = xpress::decompress_chunk(slice, 4096) {
        assert_eq!(decoded.len(), 4096);
        let _ = tracker.charge_decoded(decoded.len());
    }
    if let Ok(decoded) = lzx::decompress_chunk(slice, 32_768) {
        assert_eq!(decoded.len(), 32_768);
        let _ = tracker.charge_decoded(decoded.len());
    }

    // Native $LogFile ring/checkpoint/client-update writer roundtrip & hostile bounds.
    if slice.len() >= 16 {
        let mut table = std::collections::BTreeMap::new();
        let entry = encode_open_attribute_entry(0x80, 0, 5 | (1_u64 << 48), 0);
        let slot_off = 24_u32 + u32::from(slice[1] % 8) * 40;
        table.insert(slot_off, entry.to_vec());
        if let Ok(encoded_table) = encode_restart_table(40, &table) {
            assert!(encoded_table.len() >= 64);
        }
        let payload_len = usize::from(slice[0]) % slice.len().min(128);
        let spec = NtfsClientUpdateSpec {
            redo_op: NtfsLogOp::UpdateResidentValue,
            undo_op: NtfsLogOp::UpdateResidentValue,
            target_attribute: 24,
            record_offset: 56,
            attribute_offset: 24,
            cluster_block_offset: 0,
            target_vcn: 0,
            target_lcns: vec![4],
            redo_data: slice[..payload_len].to_vec(),
            undo_data: slice[..payload_len].to_vec(),
        };
        if let Ok(client_bytes) = encode_client_update_payload(&spec) {
            if let Ok(mut ring) = NtfsLogRingWriter::new_fresh(4096, (1, 1), 64 * 4096, 1, 1) {
                if let Ok(rec) =
                    ring.append_raw_record(LFS_RECORD_CLIENT, 24, 0, 0, &client_bytes)
                {
                    let rstr0 = ring.build_next_rstr_page(false).unwrap();
                    let rstr1 = ring.build_next_rstr_page(false).unwrap();
                    let mut mini_log = vec![0_u8; 6 * 4096];
                    mini_log[0..4096].copy_from_slice(&rstr0.bytes);
                    mini_log[4096..8192].copy_from_slice(&rstr1.bytes);
                    mini_log[4 * 4096..5 * 4096].copy_from_slice(&rec.protected_page);
                    let parsed = parse_ntfs_logfile(&mini_log).unwrap();
                    assert_eq!(parsed.records_parsed, 1);
                    assert_eq!(parsed.restart.current_lsn, rec.lsn);
                    assert_eq!(parsed.undo_actions.last().map(|a| a.lsn), Some(rec.lsn));
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
    let mode = cursor.next_u8() % 6;
    let indexed_lookup = cursor.next_bool();
    let recover_logfile = cursor.next_bool();
    let cancel_after_ops = if cursor.next_u8().is_multiple_of(8) {
        Some(1 + usize::from(cursor.next_u8() % 24))
    } else {
        None
    };

    let tracker = FuzzBudgetTracker::new(FuzzBudgets {
        max_physical_read_bytes: 4 * 1024 * 1024,
        max_decoded_bytes: 512 * 1024,
        max_retained_bytes: 512 * 1024,
        max_depth: 8,
        max_ops: 640,
        max_replica_attempts: 48,
    });

    fuzz_pure_ntfs_parsers_and_codecs(data, &tracker);

    let mut expect_corrupt_mapped = false;
    let backing = match mode {
        0 => {
            let mut raw = cursor.remainder().to_vec();
            if raw.len() < 1024 {
                raw.resize(1024, 0);
            }
            FuzzBacking::from_owned(raw)
        }
        1 => {
            let (base, digest) = ntfs_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.apply_interesting_mutations(&mut cursor, &NTFS_INTERESTING_OFFSETS, 12);
            pb.finish()
        }
        2 => {
            // Planted USA multi-sector fixup mismatch on record 25 (`mapped.bin`)
            expect_corrupt_mapped = true;
            let (base, digest) = ntfs_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.xor_byte(4 * 512 + 25 * 1024 + 1022, 0xFF);
            pb.finish()
        }
        3 => {
            // Planted out-of-range mapping-pair LCN on record 25 (`mapped.bin`)
            expect_corrupt_mapped = true;
            let (base, digest) = ntfs_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            let rec25 = 4 * 512 + 25 * 1024;
            // Corrupt MFT record magic or mapping pair run inside record 25 + update USA trailer
            let mut rec_bytes = [0_u8; 1024];
            pb.read_slice(rec25, &mut rec_bytes);
            if let Ok(mut restored) = restore_record(&rec_bytes, b"FILE") {
                // Overwrite non-resident mapping pairs at end of record with out-of-bounds LCN
                for pos in 160..restored.len().saturating_sub(16) {
                    if restored[pos..pos + 5] == [0x21, 2, 0x58, 0x02, 0] {
                        restored[pos + 2..pos + 4].copy_from_slice(&4096_u16.to_le_bytes());
                        break;
                    }
                }
                if let Ok(protected) = ffs_ondisk::ntfs::protect_record(&restored) {
                    pb.write(rec25, &protected);
                }
            }
            pb.finish()
        }
        4 => {
            // Planted `$MFTMirr` disagreement with primary `$MFT` record 0
            let (base, digest) = ntfs_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.xor_byte(128 * 512, 0xFF);
            pb.finish()
        }
        _ => {
            // Truncated NTFS backing cutting through mapped data cluster 601
            expect_corrupt_mapped = true;
            let (base, digest) = ntfs_baseline();
            let mut pb = PatchBuilder::from_static(base, digest);
            pb.truncate(600 * 512 + 256);
            pb.finish()
        }
    };

    let backing_clone = backing.clone();
    let dev = BoundedRoFuzzDevice::new(backing, Arc::clone(&tracker), cancel_after_ops);
    let cx = Cx::for_testing();

    if let Ok(vol) = NtfsVolume::from_device_with_options(
        &cx,
        Box::new(Arc::clone(&dev) as Arc<dyn ByteDevice>),
        0,
        dev.len_bytes(),
        recover_logfile,
    ) {
        if let Ok(root_rec) = vol.record(&cx, 5, None) {
            if let Ok(entries) = vol.list_directory(&cx, &root_rec) {
                let _ = tracker.charge_retained(entries.len().saturating_mul(96));
            }
        }
        let _ = vol.resolve(&cx, "/hello.txt");
        let _ = vol.resolve_indexed(&cx, "/hello.txt");
        if let Ok(rec24) = vol.record(&cx, 24, None) {
            let _ = vol.data_streams(&cx, &rec24);
            let _ = vol.reparse_point(&cx, &rec24);
            let _ = vol.extended_attributes(&cx, &rec24);
            let _ = vol.security_descriptor(&cx, &rec24);
            let note_name: Vec<u16> = "note".encode_utf16().collect();
            if let Ok(stream) = vol.data_stream(&cx, &rec24, &note_name) {
                if let Ok(bytes) = vol.read(&cx, &stream, 0, 256) {
                    let _ = tracker.charge_decoded(bytes.len());
                }
            }
        }

        let ownership_limits = RecordOwnershipLimits {
            records: 64,
            metadata_bytes: 512 * 1024,
        };
        let _ = vol.check_mft_mirror(&cx, ownership_limits);
        let _ = vol.check_record_ownership(&cx, ownership_limits);
        let _ = vol.check_allocations(
            &cx,
            AllocationLimits {
                records: 64,
                clusters: 2048,
                runs: 256,
            },
        );
        let _ = vol.check_namespace(
            &cx,
            NamespaceLimits {
                records: 64,
                metadata_bytes: 512 * 1024,
                entries: 256,
            },
        );
        let _ = vol.check_security(
            &cx,
            SecurityCheckLimits {
                entries: 64,
                metadata_bytes: 512 * 1024,
            },
        );
        let _ = vol.check_security_references(
            &cx,
            SecurityCheckLimits {
                entries: 64,
                metadata_bytes: 512 * 1024,
            },
            64,
        );
    }
    dev.assert_invariants();

    let tx_backing = backing_clone.clone();
    let facade_cx = Cx::for_testing();
    let facade_dev = BoundedRoFuzzDevice::new(
        backing_clone,
        FuzzBudgetTracker::new(FuzzBudgets::default()),
        None,
    );
    if let Ok(opened) = open_read_only_device(
        &facade_cx,
        Arc::clone(&facade_dev) as Arc<dyn ByteDevice>,
        &ReadOnlyOpenOptions {
            backend: ReadOnlyBackend::Ntfs {
                indexed_lookup,
                recover_logfile,
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
        if let Ok(mapped) = opened.filesystem.lookup(
            &facade_cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("mapped.bin"),
        ) {
            let res = opened
                .filesystem
                .read(&facade_cx, &mut scope, mapped.ino, 0, 1024);
            if expect_corrupt_mapped && cancel_after_ops.is_none() {
                assert!(
                    res.is_err(),
                    "planted NTFS USA/runlist/truncation fault must never succeed with partial bytes"
                );
            }
            assert!(matches!(
                opened
                    .filesystem
                    .write(&facade_cx, &mut scope, mapped.ino, 0, b"nope"),
                Err(FfsError::ReadOnly)
            ));
        }
    }
    facade_dev.assert_invariants();

    // Native transaction engine admission & ARIES PreviewDevice preflight against hostile media:
    // 1. Missing allow_write MUST fail closed with PermissionDenied and zero writes.
    // 2. Explicit write options against BoundedRoFuzzDevice run full bootstrap + ARIES PreviewDevice
    //    validation before attempting any write, and any attempted write fails closed with ReadOnly.
    let tx_cx = Cx::for_testing();
    let tx_dev = BoundedRoFuzzDevice::new(
        tx_backing,
        FuzzBudgetTracker::new(FuzzBudgets {
            max_physical_read_bytes: 8 * 1024 * 1024,
            max_decoded_bytes: 512 * 1024,
            max_retained_bytes: 512 * 1024,
            max_depth: 8,
            max_ops: 2048,
            max_replica_attempts: 48,
        }),
        cancel_after_ops,
    );
    assert!(matches!(
        NtfsTransactionEngine::from_device(
            &tx_cx,
            Arc::clone(&tx_dev) as Arc<dyn ByteDevice>,
            0,
            tx_dev.len_bytes(),
            NtfsWriteOptions {
                offline_image: true,
                allow_write: false,
                recover_dirty: false,
            },
        ),
        Err(FfsError::PermissionDenied | FfsError::Cancelled)
    ));
    if let Ok(mut engine) = NtfsTransactionEngine::from_device(
        &tx_cx,
        Arc::clone(&tx_dev) as Arc<dyn ByteDevice>,
        0,
        tx_dev.len_bytes(),
        NtfsWriteOptions {
            offline_image: true,
            allow_write: true,
            recover_dirty: recover_logfile,
        },
    ) {
        let outcome = engine.create_file(&tx_cx, "/", "fuzz-denied.bin", b"x");
        assert!(matches!(outcome, NtfsTxOutcome::NotCommitted(_)));
    }
    tx_dev.assert_invariants();
});
