#![forbid(unsafe_code)]
//! Native NTFS 3.1 transaction lifecycle, ARIES `$LogFile` persistence-prefix
//! fault-cut / write-reordering / torn-sector / crash-during-recovery tests,
//! `$Bitmap` & `$LogFile` exhaustion checks, and negative admission controls.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ntfs::NtfsVolume;
use ffs_ntfs::reader::allocation::{AllocationLimits, NamespaceLimits, RecordOwnershipLimits};
use ffs_ntfs::transaction::{
    NtfsPersistenceStage, NtfsTransactionEngine, NtfsTxOutcome, NtfsWriteOptions,
};
use ffs_ondisk::ntfs::index::NtfsFileName;
use ffs_ondisk::ntfs::logfile_writer::{
    LFS_RECORD_CLIENT, NtfsClientUpdateSpec, NtfsLogRingWriter, NtfsRestartConfig,
    encode_client_update_payload,
};
use ffs_ondisk::ntfs::{
    DATA, NtfsFileRecord, NtfsLogOp, NtfsReference, NtfsRun, VOLUME_INFORMATION,
    encode_mapping_pairs, restore_record,
};
use ffs_types::ByteOffset;

const SECTOR_BYTES: usize = 512;
const CLUSTER_BYTES: usize = 4096;
const RECORD_BYTES: usize = 1024;
const INDEX_BYTES: usize = 4096;
const DEFAULT_FILETIME: u64 = 133_500_000_000_000_000;

const fn write_options_clean() -> NtfsWriteOptions {
    NtfsWriteOptions {
        offline_image: true,
        allow_write: true,
        recover_dirty: false,
    }
}

const fn write_options_recover() -> NtfsWriteOptions {
    NtfsWriteOptions {
        offline_image: true,
        allow_write: true,
        recover_dirty: true,
    }
}

fn fragmented_data_fixture() -> (Arc<FaultInjectingNtfsDevice>, NtfsTransactionEngine) {
    let cx = Cx::for_testing();
    let mut image = build_clean_ntfs_image(99, 50, 0xF12A_6E17_0000_0001);
    // Give free space stale nonzero contents so a partial final cluster must
    // actually be initialized; an already-zero image would hide that bug.
    image[93 * CLUSTER_BYTES..99 * CLUSTER_BYTES].fill(0xD3);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    for index in 0_u8..4 {
        engine
            .create_file(&cx, "/", &format!("f{index}"), &vec![index; CLUSTER_BYTES])
            .into_result()
            .unwrap();
    }
    for name in ["/f0", "/f2"] {
        engine.unlink_file(&cx, name).into_result().unwrap();
    }
    engine.check_clean_consistency(&cx).unwrap();

    // Only public native operations fragmented the fixture. Ensure the test
    // cannot pass by accidentally leaving one large contiguous allocation.
    let image = device.snapshot_durable_only();
    let bitmap = &image[60 * CLUSTER_BYTES..61 * CLUSTER_BYTES];
    let mut free_count = 0;
    let mut current_run = 0;
    let mut longest_run = 0;
    for cluster in 0..99 {
        if bitmap[cluster / 8] & (1 << (cluster % 8)) == 0 {
            free_count += 1;
            current_run += 1;
            longest_run = longest_run.max(current_run);
        } else {
            current_run = 0;
        }
    }
    assert!(free_count >= 3, "fixture must have room for three clusters");
    assert!(
        longest_run < 3,
        "fixture must require fragmented allocation"
    );
    (device, engine)
}

#[test]
fn fragmented_data_create_preserves_other_files_and_zeroes_cluster_slack() {
    let cx = Cx::for_testing();
    let (device, mut engine) = fragmented_data_fixture();
    let before = device.snapshot_durable_only();
    let payload: Vec<u8> = (0..2 * CLUSTER_BYTES + 137)
        .map(|index| (index % 251) as u8)
        .collect();
    let (reference, token) = engine
        .create_file(&cx, "/", "new", &payload)
        .into_result()
        .expect("allocate three clusters across isolated free runs");
    assert!(token.matches_engine(&engine));

    let image = device.snapshot_durable_only();
    let files = read_all_files_from_clean_volume(&image);
    assert_eq!(files.get("/new"), Some(&payload));
    assert_eq!(files.get("/f1"), Some(&vec![1; CLUSTER_BYTES]));
    assert_eq!(files.get("/f3"), Some(&vec![3; CLUSTER_BYTES]));
    let record_at = CLUSTER_BYTES + reference.record as usize * RECORD_BYTES;
    let record = NtfsFileRecord::parse(&image[record_at..record_at + RECORD_BYTES]).unwrap();
    let attributes = record.attributes().unwrap();
    let data = attributes
        .iter()
        .find(|attribute| attribute.kind == DATA && attribute.name.is_empty())
        .unwrap();
    let ffs_ondisk::ntfs::NtfsValue::NonResident(stream) = &data.value else {
        panic!("three clusters must be nonresident");
    };
    let runs = ffs_ondisk::ntfs::decode_mapping_pairs(
        stream.mapping_pairs,
        stream.first_vcn,
        stream.last_vcn,
        99,
    )
    .unwrap();
    assert!(runs.len() > 1);
    let last = runs.last().unwrap();
    let slack_at = (last.lcn.unwrap() + last.clusters - 1) as usize * CLUSTER_BYTES + 137;
    assert!(
        before[slack_at..slack_at + CLUSTER_BYTES - 137]
            .iter()
            .any(|byte| *byte != 0),
        "allocated slack must contain stale bytes before initialization"
    );
    assert!(
        image[slack_at..slack_at + CLUSTER_BYTES - 137]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn fragmented_data_cow_overwrite_and_no_space_preserve_durable_contents() {
    let cx = Cx::for_testing();
    let (device, mut engine) = fragmented_data_fixture();
    let payload = vec![0xA7; 3 * CLUSTER_BYTES];
    engine
        .write_file_data(&cx, "/f1", &payload)
        .into_result()
        .expect("COW replacement can use separate free runs");
    let before = device.snapshot_durable_only();
    let files = read_all_files_from_clean_volume(&before);
    assert_eq!(files.get("/f1"), Some(&payload));
    assert_eq!(files.get("/f3"), Some(&vec![3; CLUSTER_BYTES]));
    let written = device.write_bytes_total();
    assert!(matches!(
        engine.write_file_data(&cx, "/f1", &vec![0xBB; 7 * CLUSTER_BYTES]),
        NtfsTxOutcome::NotCommitted(FfsError::NoSpace)
    ));
    assert_eq!(device.write_bytes_total(), written);
    assert_eq!(device.snapshot_live(), before);
    assert_eq!(device.snapshot_durable_only(), before);
}

#[test]
fn fragmented_data_cow_recovers_every_persistence_cut_without_mixed_contents() {
    struct Cut {
        stage: NtfsPersistenceStage,
        committed: bool,
        durable: Vec<u8>,
        live: Vec<u8>,
        reordered: Vec<u8>,
    }

    let cx = Cx::for_testing();
    let (device, mut engine) = fragmented_data_fixture();
    let before = read_all_files_from_clean_volume(&device.snapshot_durable_only());
    assert_eq!(before.get("/f1"), Some(&vec![1; CLUSTER_BYTES]));
    assert_eq!(before.get("/f3"), Some(&vec![3; CLUSTER_BYTES]));
    let cuts = Arc::new(Mutex::new(Vec::<Cut>::new()));
    {
        let captured = Arc::clone(&cuts);
        let device = Arc::clone(&device);
        let mut committed = false;
        engine.set_stage_hook(Some(Box::new(move |event| {
            committed |= event.stage == NtfsPersistenceStage::LogCommitBarrier;
            captured.lock().unwrap().push(Cut {
                stage: event.stage,
                committed,
                durable: device.snapshot_durable_only(),
                live: device.snapshot_live(),
                reordered: device.snapshot_reordered_pending(true),
            });
            Ok(())
        })));
    }

    let payload: Vec<u8> = (0..2 * CLUSTER_BYTES + 137)
        .map(|index| (index % 239) as u8)
        .collect();
    engine
        .write_file_data(&cx, "/f1", &payload)
        .into_result()
        .expect("fragmented COW replacement");
    engine.set_stage_hook(None);
    let mut after = before.clone();
    after.insert("/f1".to_owned(), payload);
    assert_eq!(
        read_all_files_from_clean_volume(&device.snapshot_durable_only()),
        after
    );

    let cuts = std::mem::take(&mut *cuts.lock().unwrap());
    assert!(
        cuts.iter()
            .filter(|cut| cut.stage == NtfsPersistenceStage::PayloadDataWrite)
            .count()
            >= 2,
        "the crash trace must include separate physical payload runs"
    );
    assert!(
        cuts.iter()
            .any(|cut| { !cut.committed && cut.stage == NtfsPersistenceStage::LogRecordWrite })
    );
    assert!(cuts.iter().any(|cut| cut.committed));

    for cut in cuts {
        // Losing all writes since the last sync preserves the old file until
        // the commit barrier; every later cut must preserve the replacement.
        let expected = if cut.committed { &after } else { &before };
        assert_eq!(
            &recover_crash_image_and_verify(&cut.durable),
            expected,
            "durable cut at {:?}",
            cut.stage
        );
        for (kind, image) in [("live", &cut.live), ("reordered", &cut.reordered)] {
            let recovered = recover_crash_image_and_verify(image);
            if cut.committed {
                assert_eq!(
                    recovered, after,
                    "{kind} cut after commit at {:?}",
                    cut.stage
                );
            } else {
                // An unflushed CommitTransaction may already be durable, so
                // either complete prefix is valid. Partial payload/bitmap
                // publication must never expose a mixture or harm /f3.
                assert!(
                    recovered == before || recovered == after,
                    "{kind} cut before commit at {:?} exposed a mixed prefix",
                    cut.stage
                );
            }
        }
    }
}

#[test]
fn attribute_list_data_replacement_refuses_without_writes() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(512, 64, 0x9988_7766_5544_3314);
    let vol_len = image.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .expect("open clean NTFS");
    let original = b"single-name file with a complete native attribute catalog";
    let (file, _) = engine
        .create_file(&cx, "/", "catalog.txt", original)
        .into_result()
        .unwrap();
    let mut image = dev.snapshot_durable_only();
    drop(engine);

    let record_at = CLUSTER_BYTES + usize::try_from(file.record).unwrap() * RECORD_BYTES;
    let raw = &image[record_at..record_at + RECORD_BYTES];
    let record = NtfsFileRecord::parse(raw).unwrap();
    let restored = restore_record(raw, b"FILE").unwrap();
    assert_eq!(record.hard_links, 1);
    let attributes = record.attributes().unwrap();
    assert_eq!(
        attributes.iter().filter(|attr| attr.kind == 0x30).count(),
        1
    );

    // A valid ATTRIBUTE_LIST catalog describes every original attribute and
    // binds its instance to this exact base record and sequence. It does not
    // list itself, require an extension record, or alter the single FILE_NAME.
    let mut catalog = Vec::new();
    for attribute in &attributes {
        let length = (26 + attribute.name.len() * 2).next_multiple_of(8);
        let mut entry = vec![0_u8; length];
        entry[..4].copy_from_slice(&attribute.kind.to_le_bytes());
        entry[4..6].copy_from_slice(&u16::try_from(length).unwrap().to_le_bytes());
        entry[6] = u8::try_from(attribute.name.len()).unwrap();
        entry[7] = 26;
        entry[16..24].copy_from_slice(&file.encode().unwrap().to_le_bytes());
        entry[24..26].copy_from_slice(&attribute.id.to_le_bytes());
        for (index, unit) in attribute.name.iter().enumerate() {
            entry[26 + index * 2..28 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        catalog.extend_from_slice(&entry);
    }
    let list_id = attributes
        .iter()
        .map(|attribute| attribute.id)
        .max()
        .unwrap()
        .checked_add(1)
        .unwrap();
    let mut file_attrs = Vec::new();
    let mut at = usize::from(u16::from_le_bytes([restored[20], restored[21]]));
    loop {
        let kind = u32::from_le_bytes(restored[at..at + 4].try_into().unwrap());
        if kind == u32::MAX {
            break;
        }
        let length = u32::from_le_bytes(restored[at + 4..at + 8].try_into().unwrap()) as usize;
        file_attrs.push(restored[at..at + length].to_vec());
        at += length;
    }
    file_attrs.push(build_resident_attr(0x20, list_id, &[], false, &catalog));
    file_attrs.sort_by_key(|attribute| u32::from_le_bytes(attribute[..4].try_into().unwrap()));
    let with_catalog = build_file_record(
        u32::try_from(file.record).unwrap(),
        file.sequence,
        1,
        false,
        &file_attrs,
    );
    image[record_at..record_at + RECORD_BYTES].copy_from_slice(&with_catalog);

    let files = read_all_files_from_clean_volume(&image);
    assert_eq!(
        files.get("/catalog.txt").map(Vec::as_slice),
        Some(original.as_slice())
    );
    let dev = FaultInjectingNtfsDevice::new(image.clone());
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .expect("complete base-only attribute catalog passes clean admission");
    let before_writes = dev.write_bytes_total();
    let outcome = engine.write_file_data(&cx, "/catalog.txt", &vec![0xA7; 3 * CLUSTER_BYTES]);
    assert!(
        matches!(
            outcome,
            NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
        ),
        "ATTRIBUTE_LIST replacement requires coordinated catalog updates: {outcome:?}"
    );
    assert_eq!(dev.write_bytes_total(), before_writes);
    assert_eq!(dev.snapshot_live(), image);
    assert_eq!(dev.snapshot_durable_only(), image);
    engine.check_clean_consistency(&cx).unwrap();
}

fn protect_record_bytes(mut raw: Vec<u8>, token: u16) -> Vec<u8> {
    let usa = usize::from(u16::from_le_bytes([raw[4], raw[5]]));
    let count = usize::from(u16::from_le_bytes([raw[6], raw[7]]));
    raw[usa..usa + 2].copy_from_slice(&token.to_le_bytes());
    for sector in 1..count {
        let end = sector * SECTOR_BYTES;
        let saved = [raw[end - 2], restored_byte(&raw, end - 1)];
        raw[usa + sector * 2..usa + sector * 2 + 2].copy_from_slice(&saved);
        raw[end - 2..end].copy_from_slice(&token.to_le_bytes());
    }
    raw
}

const fn restored_byte(raw: &[u8], idx: usize) -> u8 {
    raw[idx]
}

fn build_resident_attr(kind: u32, id: u16, name: &[u16], indexed: bool, val: &[u8]) -> Vec<u8> {
    let name_bytes = name.len() * 2;
    let val_off = (24 + name_bytes + 7) & !7;
    let total = (val_off + val.len() + 7) & !7;
    let mut out = vec![0_u8; total];
    out[0..4].copy_from_slice(&kind.to_le_bytes());
    out[4..8].copy_from_slice(&(total as u32).to_le_bytes());
    out[8] = 0;
    out[9] = u8::try_from(name.len()).expect("attr name len");
    out[10..12].copy_from_slice(&(24_u16).to_le_bytes());
    out[14..16].copy_from_slice(&id.to_le_bytes());
    out[16..20].copy_from_slice(&(val.len() as u32).to_le_bytes());
    out[20..22].copy_from_slice(&(val_off as u16).to_le_bytes());
    out[22] = u8::from(indexed);
    for (i, &ch) in name.iter().enumerate() {
        let at = 24 + i * 2;
        out[at..at + 2].copy_from_slice(&ch.to_le_bytes());
    }
    out[val_off..val_off + val.len()].copy_from_slice(val);
    out
}

fn build_nonresident_attr(
    kind: u32,
    id: u16,
    name: &[u16],
    lcn: u64,
    clusters: u64,
    logical_size: u64,
    total_clusters: u64,
) -> Vec<u8> {
    let run = NtfsRun {
        vcn: 0,
        clusters,
        lcn: Some(lcn),
    };
    let (pairs, last_vcn) = encode_mapping_pairs(&[run], 0, total_clusters).expect("encode pairs");
    let name_bytes = name.len() * 2;
    let map_off = (64 + name_bytes + 7) & !7;
    let total = (map_off + pairs.len() + 7) & !7;
    let alloc_bytes = clusters * (CLUSTER_BYTES as u64);
    let mut out = vec![0_u8; total];
    out[0..4].copy_from_slice(&kind.to_le_bytes());
    out[4..8].copy_from_slice(&(total as u32).to_le_bytes());
    out[8] = 1;
    out[9] = u8::try_from(name.len()).expect("attr name len");
    out[10..12].copy_from_slice(&(64_u16).to_le_bytes());
    out[14..16].copy_from_slice(&id.to_le_bytes());
    out[16..24].copy_from_slice(&0_u64.to_le_bytes());
    out[24..32].copy_from_slice(&last_vcn.to_le_bytes());
    out[32..34].copy_from_slice(&(map_off as u16).to_le_bytes());
    out[40..48].copy_from_slice(&alloc_bytes.to_le_bytes());
    out[48..56].copy_from_slice(&logical_size.to_le_bytes());
    out[56..64].copy_from_slice(&logical_size.to_le_bytes());
    for (i, &ch) in name.iter().enumerate() {
        let at = 64 + i * 2;
        out[at..at + 2].copy_from_slice(&ch.to_le_bytes());
    }
    out[map_off..map_off + pairs.len()].copy_from_slice(&pairs);
    out
}

fn build_file_record(
    number: u32,
    sequence: u16,
    hard_links: u16,
    is_dir: bool,
    attrs: &[Vec<u8>],
) -> Vec<u8> {
    let mut raw = vec![0_u8; RECORD_BYTES];
    raw[0..4].copy_from_slice(b"FILE");
    raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
    raw[16..18].copy_from_slice(&sequence.to_le_bytes());
    raw[18..20].copy_from_slice(&hard_links.to_le_bytes());
    raw[20..22].copy_from_slice(&56_u16.to_le_bytes());
    let flags: u16 = if is_dir { 0x0003 } else { 0x0001 };
    raw[22..24].copy_from_slice(&flags.to_le_bytes());
    raw[28..32].copy_from_slice(&(RECORD_BYTES as u32).to_le_bytes());
    raw[40..42].copy_from_slice(&u16::try_from(attrs.len()).unwrap().to_le_bytes());
    raw[44..48].copy_from_slice(&number.to_le_bytes());
    let mut pos = 56;
    for a in attrs {
        raw[pos..pos + a.len()].copy_from_slice(a);
        pos += a.len();
    }
    raw[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    raw[24..28].copy_from_slice(&((pos + 8) as u32).to_le_bytes());
    let protected = protect_record_bytes(raw, 0x2468);
    NtfsFileRecord::parse(&protected).expect("valid synthetic FILE record");
    protected
}

fn build_root_security_descriptor() -> Vec<u8> {
    let mut sd = vec![0_u8; 52];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
    sd[4..8].copy_from_slice(&20_u32.to_le_bytes());
    sd[8..12].copy_from_slice(&32_u32.to_le_bytes());
    sd[16..20].copy_from_slice(&44_u32.to_le_bytes());
    let sid = [1_u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    sd[20..32].copy_from_slice(&sid);
    sd[32..44].copy_from_slice(&sid);
    sd[44] = 2;
    sd[46..48].copy_from_slice(&8_u16.to_le_bytes());
    sd
}

fn build_empty_i30_root() -> Vec<u8> {
    let mut root = vec![0_u8; 48];
    root[0..4].copy_from_slice(&0x30_u32.to_le_bytes());
    root[4..8].copy_from_slice(&1_u32.to_le_bytes());
    root[8..12].copy_from_slice(&(INDEX_BYTES as u32).to_le_bytes());
    root[12] = 1;
    root[16..20].copy_from_slice(&16_u32.to_le_bytes());
    root[20..24].copy_from_slice(&32_u32.to_le_bytes());
    root[24..28].copy_from_slice(&32_u32.to_le_bytes());
    root[32 + 8..32 + 10].copy_from_slice(&16_u16.to_le_bytes());
    root[32 + 12..32 + 16].copy_from_slice(&2_u32.to_le_bytes());
    root
}

/// Build a clean, 4-checker-consistent NTFS 3.1 volume image in memory.
fn build_clean_ntfs_image(total_clusters: u64, log_pages: u64, serial: u64) -> Vec<u8> {
    assert!(log_pages >= 50);
    let mft_lcn = 1_u64;
    let mirr_lcn = 9_u64;
    let log_lcn = 10_u64;
    let bm_lcn = 10 + log_pages;
    let upcase_lcn = 11 + log_pages;
    let used_clusters = upcase_lcn + 32;
    assert!(total_clusters >= used_clusters + 4);

    let volume_bytes = total_clusters * (CLUSTER_BYTES as u64);
    let mut img = vec![0_u8; usize::try_from(volume_bytes).unwrap() + SECTOR_BYTES];

    {
        let boot = &mut img[0..SECTOR_BYTES];
        boot[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[11..13].copy_from_slice(&(SECTOR_BYTES as u16).to_le_bytes());
        boot[13] = u8::try_from(CLUSTER_BYTES / SECTOR_BYTES).unwrap();
        boot[21] = 0xF8;
        boot[24..26].copy_from_slice(&63_u16.to_le_bytes());
        boot[26..28].copy_from_slice(&255_u16.to_le_bytes());
        boot[36] = 0x80;
        boot[38] = 0x80;
        let total_sectors = volume_bytes / (SECTOR_BYTES as u64);
        boot[40..48].copy_from_slice(&total_sectors.to_le_bytes());
        boot[48..56].copy_from_slice(&mft_lcn.to_le_bytes());
        boot[56..64].copy_from_slice(&mirr_lcn.to_le_bytes());
        boot[64] = 0xF6;
        boot[68] = 1;
        boot[72..80].copy_from_slice(&serial.to_le_bytes());
        boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    }
    let boot_copy = img[0..SECTOR_BYTES].to_vec();
    let vol_end = usize::try_from(volume_bytes).unwrap();
    img[vol_end..vol_end + SECTOR_BYTES].copy_from_slice(&boot_copy);

    let log_off = usize::try_from(log_lcn).unwrap() * CLUSTER_BYTES;
    let logfile_byte_len = usize::try_from(log_pages).unwrap() * CLUSTER_BYTES;
    img[log_off..log_off + logfile_byte_len].fill(0xFF);

    let up_off = usize::try_from(upcase_lcn).unwrap() * CLUSTER_BYTES;
    for cp in 0_u32..65_536 {
        let mapped = if (u32::from(b'a')..=u32::from(b'z')).contains(&cp) {
            u16::try_from(cp - 32).unwrap()
        } else {
            u16::try_from(cp).unwrap()
        };
        let at = up_off + (cp as usize) * 2;
        img[at..at + 2].copy_from_slice(&mapped.to_le_bytes());
    }

    let bm_logical = usize::try_from(total_clusters.div_ceil(8)).unwrap();
    let bm_off = usize::try_from(bm_lcn).unwrap() * CLUSTER_BYTES;
    for c in 0..used_clusters {
        img[bm_off + usize::try_from(c / 8).unwrap()] |= 1_u8 << (c % 8);
    }

    let mut mft_bm = [0_u8; 8];
    for slot in [0_u64, 1, 2, 3, 5, 6, 7, 10] {
        mft_bm[usize::try_from(slot / 8).unwrap()] |= 1_u8 << (slot % 8);
    }
    let rec0 = build_file_record(
        0,
        1,
        0,
        false,
        &[
            build_nonresident_attr(
                DATA,
                0,
                &[],
                mft_lcn,
                8,
                32 * RECORD_BYTES as u64,
                total_clusters,
            ),
            build_resident_attr(0xB0, 1, &[], false, &mft_bm),
        ],
    );
    let rec1 = build_file_record(
        1,
        1,
        0,
        false,
        &[build_nonresident_attr(
            DATA,
            0,
            &[],
            mirr_lcn,
            1,
            4 * RECORD_BYTES as u64,
            total_clusters,
        )],
    );
    let rec2 = build_file_record(
        2,
        1,
        0,
        false,
        &[build_nonresident_attr(
            DATA,
            0,
            &[],
            log_lcn,
            log_pages,
            log_pages * CLUSTER_BYTES as u64,
            total_clusters,
        )],
    );
    let mut vol_info = [0_u8; 12];
    vol_info[8..10].copy_from_slice(&[3, 1]);
    let rec3 = build_file_record(
        3,
        1,
        0,
        false,
        &[build_resident_attr(
            VOLUME_INFORMATION,
            0,
            &[],
            false,
            &vol_info,
        )],
    );

    let mut std5 = [0_u8; 48];
    for off in [0_usize, 8, 16, 24] {
        std5[off..off + 8].copy_from_slice(&DEFAULT_FILETIME.to_le_bytes());
    }
    let root_fn = NtfsFileName {
        parent: NtfsReference {
            record: 5,
            sequence: 5,
        },
        namespace: 3,
        name: vec![u16::from(b'.')],
    }
    .encode(
        DEFAULT_FILETIME,
        DEFAULT_FILETIME,
        DEFAULT_FILETIME,
        DEFAULT_FILETIME,
        0,
        0,
        0x1000_0000,
        0,
    )
    .expect("encode root dot");
    let i30_name = [
        u16::from(b'$'),
        u16::from(b'I'),
        u16::from(b'3'),
        u16::from(b'0'),
    ];
    let rec5 = build_file_record(
        5,
        5,
        1,
        true,
        &[
            build_resident_attr(0x10, 0, &[], false, &std5),
            build_resident_attr(0x30, 1, &[], true, &root_fn),
            build_resident_attr(0x50, 2, &[], false, &build_root_security_descriptor()),
            build_resident_attr(0x90, 3, &i30_name, false, &build_empty_i30_root()),
        ],
    );
    let rec6 = build_file_record(
        6,
        1,
        0,
        false,
        &[build_nonresident_attr(
            DATA,
            0,
            &[],
            bm_lcn,
            1,
            bm_logical as u64,
            total_clusters,
        )],
    );
    let rec7 = build_file_record(
        7,
        1,
        0,
        false,
        &[build_nonresident_attr(
            DATA,
            0,
            &[],
            0,
            1,
            CLUSTER_BYTES as u64,
            total_clusters,
        )],
    );
    let upcase_rec10 = build_file_record(
        10,
        1,
        0,
        false,
        &[build_nonresident_attr(
            DATA,
            0,
            &[],
            upcase_lcn,
            32,
            131_072,
            total_clusters,
        )],
    );

    let mft_base = usize::try_from(mft_lcn).unwrap() * CLUSTER_BYTES;
    for (slot, bytes) in [
        (0_usize, &rec0),
        (1, &rec1),
        (2, &rec2),
        (3, &rec3),
        (5, &rec5),
        (6, &rec6),
        (7, &rec7),
        (10, &upcase_rec10),
    ] {
        let off = mft_base + slot * RECORD_BYTES;
        img[off..off + RECORD_BYTES].copy_from_slice(bytes);
    }

    let mirr_base = usize::try_from(mirr_lcn).unwrap() * CLUSTER_BYTES;
    let first4 = img[mft_base..mft_base + 4 * RECORD_BYTES].to_vec();
    img[mirr_base..mirr_base + 4 * RECORD_BYTES].copy_from_slice(&first4);

    img
}

/// Fault-injecting backing device tracking `durable` (flushed via `sync()`) vs
/// `pending` (un-flushed writes since the last `sync()`).
struct FaultInjectingNtfsDevice {
    state: Mutex<FaultState>,
}

struct FaultState {
    durable: Vec<u8>,
    live: Vec<u8>,
    pending: Vec<(u64, Vec<u8>)>,
    sync_calls: usize,
    fail_sync_call: Option<usize>,
    write_bytes_total: u64,
}

impl FaultInjectingNtfsDevice {
    fn new(initial: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FaultState {
                live: initial.clone(),
                durable: initial,
                pending: Vec::new(),
                sync_calls: 0,
                fail_sync_call: None,
                write_bytes_total: 0,
            }),
        })
    }

    fn set_fail_sync_call(&self, call_one_based: Option<usize>) {
        let mut st = self.state.lock().unwrap();
        st.sync_calls = 0;
        st.fail_sync_call = call_one_based;
    }

    fn write_bytes_total(&self) -> u64 {
        self.state.lock().unwrap().write_bytes_total
    }

    fn snapshot_live(&self) -> Vec<u8> {
        self.state.lock().unwrap().live.clone()
    }

    fn snapshot_durable_only(&self) -> Vec<u8> {
        self.state.lock().unwrap().durable.clone()
    }

    fn snapshot_reordered_pending(&self, drop_odd_pending: bool) -> Vec<u8> {
        let st = self.state.lock().unwrap();
        let mut img = st.durable.clone();
        for (idx, (off, bytes)) in st.pending.iter().rev().enumerate() {
            if drop_odd_pending && idx % 2 == 1 {
                continue;
            }
            let at = usize::try_from(*off).unwrap();
            img[at..at + bytes.len()].copy_from_slice(bytes);
        }
        img
    }
}

impl ByteDevice for FaultInjectingNtfsDevice {
    fn len_bytes(&self) -> u64 {
        self.state.lock().unwrap().live.len() as u64
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let st = self.state.lock().unwrap();
        let at = usize::try_from(offset.0).unwrap();
        buf.copy_from_slice(&st.live[at..at + buf.len()]);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        let at = usize::try_from(offset.0).unwrap();
        st.live[at..at + buf.len()].copy_from_slice(buf);
        st.pending.push((offset.0, buf.to_vec()));
        st.write_bytes_total += buf.len() as u64;
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        st.sync_calls += 1;
        if st.fail_sync_call == Some(st.sync_calls) {
            return Err(FfsError::Io(std::io::Error::other(
                "injected ByteDevice::sync barrier failure",
            )));
        }
        let pending = std::mem::take(&mut st.pending);
        for (off, bytes) in pending {
            let at = usize::try_from(off).unwrap();
            st.durable[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        Ok(())
    }
}

struct ArcDevice(Arc<FaultInjectingNtfsDevice>);

impl ByteDevice for ArcDevice {
    fn len_bytes(&self) -> u64 {
        self.0.len_bytes()
    }
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        self.0.read_exact_at(cx, offset, buf)
    }
    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        self.0.write_all_at(cx, offset, buf)
    }
    fn sync(&self, cx: &Cx) -> Result<()> {
        self.0.sync(cx)
    }
}

fn read_all_files_from_clean_volume(image: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let cx = Cx::for_testing();
    let dev = FaultInjectingNtfsDevice::new(image.to_vec());
    let vol_len = image.len() as u64 - SECTOR_BYTES as u64;
    let volume = NtfsVolume::from_device(&cx, Box::new(ArcDevice(dev)), 0, vol_len)
        .expect("fresh NtfsVolume open");

    let alloc = volume
        .check_allocations(&cx, AllocationLimits::default())
        .expect("check_allocations");
    assert!(
        alloc.is_consistent(),
        "allocation issues: {:?}",
        alloc.issues
    );
    let own = volume
        .check_record_ownership(&cx, RecordOwnershipLimits::default())
        .expect("check_record_ownership");
    assert!(own.is_consistent(), "ownership issues: {:?}", own.issues);
    let mirr = volume
        .check_mft_mirror(&cx, RecordOwnershipLimits::default())
        .expect("check_mft_mirror");
    assert!(mirr.is_consistent(), "mirror issues: {:?}", mirr.issues);
    let ns = volume
        .check_namespace(&cx, NamespaceLimits::default())
        .expect("check_namespace");
    assert!(ns.is_consistent(), "namespace issues: {:?}", ns.issues);

    let root_rec = volume.record(&cx, 5, Some(5)).expect("root record 5");
    let mut out = BTreeMap::new();
    collect_tree(&cx, &volume, &root_rec, "", &mut out);
    out
}

fn collect_tree(
    cx: &Cx,
    volume: &NtfsVolume,
    dir_rec: &NtfsFileRecord,
    dir_prefix: &str,
    out: &mut BTreeMap<String, Vec<u8>>,
) {
    let entries = volume.list_directory(cx, dir_rec).expect("list_directory");
    for entry in entries {
        let name = String::from_utf16(&entry.filename.name).expect("utf16 entry");
        if name == "." {
            continue;
        }
        let full = format!("{dir_prefix}/{name}");
        let rec = volume
            .record(cx, entry.reference.record, Some(entry.reference.sequence))
            .expect("entry record");
        if rec.is_directory() {
            out.insert(format!("{full}/"), Vec::new());
            collect_tree(cx, volume, &rec, &full, out);
        } else {
            let stream = volume
                .data_stream(cx, &rec, &[])
                .expect("open unnamed DATA");
            let bytes = volume
                .read(cx, &stream, 0, usize::try_from(stream.size).unwrap())
                .expect("read file bytes");
            out.insert(full, bytes);
        }
    }
}

fn recover_crash_image_and_verify(crash_image: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let cx = Cx::for_testing();
    let vol_len = crash_image.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(crash_image.to_vec());
    let engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_recover(),
    )
    .expect("fresh NtfsTransactionEngine persistent ARIES recovery");
    engine
        .check_clean_consistency(&cx)
        .expect("4-checker clean consistency after persistent ARIES recovery");
    read_all_files_from_clean_volume(&dev.snapshot_live())
}

#[test]
fn clean_admission_and_end_to_end_lifecycle_passes_all_four_checkers() {
    let cx = Cx::for_testing();
    let img = build_clean_ntfs_image(512, 64, 0x1122_3344_5566_7788);
    let vol_len = img.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(img);

    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .expect("admit clean NTFS 3.1 volume");

    let (docs_ref, tok1) = engine.mkdir(&cx, "/", "docs").into_result().unwrap();
    assert!(tok1.matches_engine(&engine));
    assert!(docs_ref.record >= 24);

    let (readme_ref, tok2) = engine
        .create_file(&cx, "/docs", "readme.txt", b"hello resident ntfs")
        .into_result()
        .unwrap();
    assert!(tok2.matches_engine(&engine));
    assert!(tok2.commit_lsn() > tok1.commit_lsn());

    let large_v1: Vec<u8> = (0_u32..9_500)
        .map(|i| u8::try_from((i * 7 + 3) & 0xFF).unwrap())
        .collect();
    let (blob_ref, tok3) = engine
        .create_file(&cx, "/docs", "blob.bin", &large_v1)
        .into_result()
        .unwrap();
    assert!(tok3.matches_engine(&engine));

    // Resident -> resident resize
    engine
        .write_file_data(
            &cx,
            "/docs/readme.txt",
            b"updated resident payload with more bytes!",
        )
        .into_result()
        .unwrap();

    // Resident -> nonresident promotion
    let promoted: Vec<u8> = (0_u32..6_200)
        .map(|i| u8::try_from((i * 13 + 9) & 0xFF).unwrap())
        .collect();
    engine
        .write_file_data(&cx, "/docs/readme.txt", &promoted)
        .into_result()
        .unwrap();

    // Nonresident -> disjoint nonresident COW overwrite
    let large_v2: Vec<u8> = (0_u32..12_800)
        .map(|i| u8::try_from((i * 3 + 17) & 0xFF).unwrap())
        .collect();
    engine
        .write_file_data(&cx, "/docs/blob.bin", &large_v2)
        .into_result()
        .unwrap();

    // Nonresident -> empty (0 bytes resident) -> small resident
    engine
        .write_file_data(&cx, "/docs/blob.bin", b"")
        .into_result()
        .unwrap();
    engine
        .write_file_data(&cx, "/docs/blob.bin", b"shrunk back to resident")
        .into_result()
        .unwrap();

    // Same-dir + cross-dir renames
    engine.mkdir(&cx, "/", "archive").into_result().unwrap();
    engine
        .rename_entry(&cx, "/docs/readme.txt", "/docs/guide.txt", Some(readme_ref))
        .into_result()
        .unwrap();
    engine
        .rename_entry(
            &cx,
            "/docs/guide.txt",
            "/archive/guide.txt",
            Some(readme_ref),
        )
        .into_result()
        .unwrap();

    // Unlink blob.bin and verify slot reuse increments sequence number!
    let unlinked_ref = engine
        .unlink_file(&cx, "/docs/blob.bin")
        .into_result()
        .unwrap()
        .0;
    assert_eq!(unlinked_ref, blob_ref);
    let (reused_ref, _) = engine
        .create_file(&cx, "/docs", "reused.txt", b"reallocated mft slot")
        .into_result()
        .unwrap();
    assert_eq!(reused_ref.record, blob_ref.record);
    assert_eq!(reused_ref.sequence, blob_ref.sequence + 1);

    // Grow $MFT explicitly from 32 -> 48 logical slots and verify $MFTMirr record 0 stays in sync!
    let (new_mft_slots, tok_grow) = engine.grow_mft(&cx, 16).into_result().unwrap();
    assert_eq!(new_mft_slots, 48);
    assert!(tok_grow.matches_engine(&engine));

    let tree = read_all_files_from_clean_volume(&dev.snapshot_live());
    assert_eq!(tree.get("/archive/guide.txt"), Some(&promoted));
    assert_eq!(
        tree.get("/docs/reused.txt").map(Vec::as_slice),
        Some(b"reallocated mft slot".as_slice())
    );
    assert!(!tree.contains_key("/docs/blob.bin"));
    assert!(!tree.contains_key("/docs/readme.txt"));
}

#[test]
fn rename_rejects_case_folded_directory_ancestry_without_writes() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(512, 64, 0x7A11_C1C1_E000_0001);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    let (docs, _) = engine.mkdir(&cx, "/", "docs").into_result().unwrap();
    let (sub, _) = engine.mkdir(&cx, "/docs", "sub").into_result().unwrap();
    engine
        .create_file(&cx, "/docs/sub", "keep.txt", b"reachable native data")
        .into_result()
        .unwrap();
    let before = device.snapshot_live();
    let writes = device.write_bytes_total();
    let trace_len = engine.persistence_trace().len();

    for (source, destination, identity) in [
        ("/docs", "/DOCS/moved", docs),
        ("/DOCS", "/docs/sub/moved", docs),
        ("/docs", "/DoCs/SuB/moved", docs),
        ("/docs/sub", "/DOCS/SUB/moved", sub),
    ] {
        let outcome = engine.rename_entry(&cx, source, destination, Some(identity));
        assert!(
            matches!(outcome, NtfsTxOutcome::NotCommitted(FfsError::Format(_))),
            "rename {source} -> {destination} must reject a native directory cycle: {outcome:?}"
        );
        assert_eq!(device.write_bytes_total(), writes);
        assert_eq!(device.snapshot_live(), before);
        assert_eq!(engine.persistence_trace().len(), trace_len);
        engine.check_clean_consistency(&cx).unwrap();
    }
    let tree = read_all_files_from_clean_volume(&device.snapshot_live());
    assert_eq!(
        tree.get("/docs/sub/keep.txt").map(Vec::as_slice),
        Some(b"reachable native data".as_slice())
    );
}

#[test]
fn rename_uses_native_source_spelling_and_sequence_identity() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(512, 64, 0x7A11_C1C1_E000_0002);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    let (docs, _) = engine.mkdir(&cx, "/", "docs").into_result().unwrap();
    engine.mkdir(&cx, "/", "archive").into_result().unwrap();
    let (readme, _) = engine
        .create_file(&cx, "/docs", "ReadMe.txt", b"same native file")
        .into_result()
        .unwrap();

    let before = device.snapshot_live();
    let writes = device.write_bytes_total();
    let stale = NtfsReference {
        record: readme.record,
        sequence: readme.sequence.wrapping_add(1),
    };
    assert!(matches!(
        engine.rename_entry(&cx, "/DOCS/README.TXT", "/ARCHIVE/renamed.txt", Some(stale)),
        NtfsTxOutcome::NotCommitted(FfsError::Corruption { .. })
    ));
    assert_eq!(device.write_bytes_total(), writes);
    assert_eq!(device.snapshot_live(), before);

    let (moved, token) = engine
        .rename_entry(
            &cx,
            "/DOCS/README.TXT",
            "/ARCHIVE/renamed.txt",
            Some(readme),
        )
        .into_result()
        .unwrap();
    assert_eq!(moved, readme);
    assert!(token.matches_engine(&engine));
    engine.check_clean_consistency(&cx).unwrap();

    let (case_renamed, _) = engine
        .rename_entry(
            &cx,
            "/ARCHIVE/RENAMED.TXT",
            "/archive/Renamed.txt",
            Some(readme),
        )
        .into_result()
        .unwrap();
    assert_eq!(case_renamed, readme);
    engine.check_clean_consistency(&cx).unwrap();

    let (moved_directory, _) = engine
        .rename_entry(&cx, "/DOCS", "/ARCHIVE/documents", Some(docs))
        .into_result()
        .unwrap();
    assert_eq!(moved_directory, docs);
    let tree = read_all_files_from_clean_volume(&device.snapshot_live());
    assert_eq!(
        tree.get("/archive/Renamed.txt").map(Vec::as_slice),
        Some(b"same native file".as_slice())
    );
    assert!(tree.contains_key("/archive/documents/"));
    assert!(!tree.contains_key("/docs/"));
}

#[test]
fn rename_and_unlink_refuse_coupled_native_aliases_without_mutating_either_name() {
    fn raw_attributes(record: &NtfsFileRecord) -> Vec<Vec<u8>> {
        let bytes = record.used_bytes();
        let mut offset = usize::from(u16::from_le_bytes([bytes[20], bytes[21]]));
        let mut attributes = Vec::new();
        while bytes[offset..offset + 4] != u32::MAX.to_le_bytes() {
            let length =
                u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
            attributes.push(bytes[offset..offset + length].to_vec());
            offset += length;
        }
        attributes
    }

    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(512, 64, 0x7A11_C1C1_E000_0003);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    let (file_ref, _) = engine
        .create_file(&cx, "/", "NativeLongName.txt", b"one file, two names")
        .into_result()
        .unwrap();
    let view = engine.volume_view(&cx).unwrap();
    let record = view
        .record(&cx, file_ref.record, Some(file_ref.sequence))
        .unwrap();
    let root = view.record(&cx, 5, Some(5)).unwrap();
    let alias = NtfsFileName {
        parent: NtfsReference {
            record: 5,
            sequence: 5,
        },
        namespace: 2,
        name: "NATIVE~1.TXT".encode_utf16().collect(),
    }
    .encode(
        DEFAULT_FILETIME,
        DEFAULT_FILETIME,
        DEFAULT_FILETIME,
        DEFAULT_FILETIME,
        24,
        19,
        0x20,
        0,
    )
    .unwrap();
    let mut attributes = raw_attributes(&record);
    attributes.push(build_resident_attr(
        0x30,
        u16::try_from(attributes.len()).unwrap(),
        &[],
        true,
        &alias,
    ));
    attributes.sort_by_key(|attr| u32::from_le_bytes(attr[..4].try_into().unwrap()));
    let aliased_record = build_file_record(record.number, record.sequence, 2, false, &attributes);

    let root_attrs = root.attributes().unwrap();
    let index_attr = root_attrs.iter().find(|attr| attr.kind == 0x90).unwrap();
    let ffs_ondisk::ntfs::NtfsValue::Resident(index) = &index_attr.value else {
        panic!("fixture root index must be resident");
    };
    let mut index = index.to_vec();
    let terminal = index.split_off(index.len() - 16);
    index.extend(ffs_ondisk::ntfs::index::encode_index_entry(file_ref, &alias, None).unwrap());
    index.extend(terminal);
    let used = u32::try_from(index.len() - 16).unwrap();
    index[20..24].copy_from_slice(&used.to_le_bytes());
    index[24..28].copy_from_slice(&used.to_le_bytes());
    let mut root_raw_attrs = raw_attributes(&root);
    let index_position = root_raw_attrs
        .iter()
        .position(|attr| attr[..4] == 0x90_u32.to_le_bytes())
        .unwrap();
    root_raw_attrs[index_position] =
        build_resident_attr(0x90, index_attr.id, &index_attr.name, false, &index);
    let aliased_root = build_file_record(5, 5, root.hard_links, true, &root_raw_attrs);
    let mut aliased_image = device.snapshot_live();
    let file_offset = CLUSTER_BYTES + usize::try_from(file_ref.record).unwrap() * RECORD_BYTES;
    aliased_image[file_offset..file_offset + RECORD_BYTES].copy_from_slice(&aliased_record);
    let root_offset = CLUSTER_BYTES + 5 * RECORD_BYTES;
    aliased_image[root_offset..root_offset + RECORD_BYTES].copy_from_slice(&aliased_root);

    // Admit the complete two-name image through all unchanged native checkers.
    // The negative control must not rely on malformed input to prevent writes.
    let device = FaultInjectingNtfsDevice::new(aliased_image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    let before = device.snapshot_live();
    for source in ["/NativeLongName.txt", "/NATIVE~1.TXT"] {
        let outcome = engine.rename_entry(&cx, source, "/renamed.txt", Some(file_ref));
        assert!(matches!(
            outcome,
            NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
        ));
        assert!(matches!(
            engine.unlink_file(&cx, source),
            NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
        ));
        assert!(matches!(
            engine.write_file_data(&cx, source, &vec![0xA7; 3 * CLUSTER_BYTES]),
            NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
        ));
        assert!(matches!(
            engine.write_file_range(&cx, source, 3, b"replacement"),
            NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
        ));
        assert!(matches!(
            engine.truncate_file(&cx, source, 4),
            NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
        ));
        assert_eq!(device.write_bytes_total(), 0);
        assert_eq!(device.snapshot_live(), before);
        assert_eq!(device.snapshot_durable_only(), before);
        assert!(engine.persistence_trace().is_empty());
    }
    let tree = read_all_files_from_clean_volume(&device.snapshot_live());
    assert_eq!(tree.get("/NativeLongName.txt"), tree.get("/NATIVE~1.TXT"));
    assert_eq!(
        tree.get("/NativeLongName.txt").map(Vec::as_slice),
        Some(b"one file, two names".as_slice())
    );
}

#[test]
fn unlink_reclaims_empty_external_directory_and_named_stream_after_native_case_lookup() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(512, 64, 0x7A11_C1C1_E000_0004);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    let (directory, _) = engine.mkdir(&cx, "/", "Archive").into_result().unwrap();
    for number in 0..12 {
        let name = format!("entry_{number:02}_extended_filename_for_external_index.txt");
        engine
            .create_file(&cx, "/Archive", &name, b"native child")
            .into_result()
            .unwrap();
    }
    let before = device.snapshot_live();
    let writes = device.write_bytes_total();
    assert!(matches!(
        engine.unlink_file(&cx, "/ARCHIVE"),
        NtfsTxOutcome::NotCommitted(FfsError::NotEmpty)
    ));
    assert_eq!(device.snapshot_live(), before);
    assert_eq!(device.write_bytes_total(), writes);

    for number in 0..12 {
        let path = format!("/ARCHIVE/ENTRY_{number:02}_EXTENDED_FILENAME_FOR_EXTERNAL_INDEX.TXT");
        engine.unlink_file(&cx, &path).into_result().unwrap();
    }
    engine.check_clean_consistency(&cx).unwrap();

    // A directory may own both external $I30 allocation and a named DATA
    // stream. Both allocations must retire with the same logged unlink.
    let image = device.snapshot_live();
    let record_offset = CLUSTER_BYTES + usize::try_from(directory.record).unwrap() * RECORD_BYTES;
    let mut attributes =
        copied_test_record_attributes(&image[record_offset..record_offset + RECORD_BYTES]);
    assert!(
        attributes
            .iter()
            .any(|attr| attr[..4] == 0xA0_u32.to_le_bytes())
    );
    let named_cluster = 500_u64;
    let named_name: Vec<u16> = "directory-notes".encode_utf16().collect();
    attributes.push(build_nonresident_attr(
        DATA,
        30,
        &named_name,
        named_cluster,
        1,
        5,
        512,
    ));
    attributes.sort_by_key(|attr| u32::from_le_bytes(attr[..4].try_into().unwrap()));
    let changed = build_file_record(
        directory.record as u32,
        directory.sequence,
        1,
        true,
        &attributes,
    );
    device
        .write_all_at(&cx, ByteOffset(record_offset as u64), &changed)
        .unwrap();
    device
        .write_all_at(
            &cx,
            ByteOffset(named_cluster * CLUSTER_BYTES as u64),
            b"notes",
        )
        .unwrap();
    let bitmap_byte = 74 * CLUSTER_BYTES + usize::try_from(named_cluster / 8).unwrap();
    let bitmap_mask = 1_u8 << (named_cluster % 8);
    assert_eq!(image[bitmap_byte] & bitmap_mask, 0);
    device
        .write_all_at(
            &cx,
            ByteOffset(bitmap_byte as u64),
            &[image[bitmap_byte] | bitmap_mask],
        )
        .unwrap();
    device.sync(&cx).unwrap();
    engine.check_clean_consistency(&cx).unwrap();
    let view = engine.volume_view(&cx).unwrap();
    let record = view
        .record(&cx, directory.record, Some(directory.sequence))
        .unwrap();
    let notes = view.data_stream(&cx, &record, &named_name).unwrap();
    assert_eq!(view.read(&cx, &notes, 0, 5).unwrap(), b"notes");
    let mut owned_clusters = Vec::new();
    for attribute in record.attributes().unwrap() {
        if let ffs_ondisk::ntfs::NtfsValue::NonResident(extent) = attribute.value {
            for run in ffs_ondisk::ntfs::decode_mapping_pairs(
                extent.mapping_pairs,
                extent.first_vcn,
                extent.last_vcn,
                512,
            )
            .unwrap()
            {
                if let Some(lcn) = run.lcn {
                    owned_clusters.extend(lcn..lcn + run.clusters);
                }
            }
        }
    }
    assert!(owned_clusters.contains(&named_cluster));
    assert!(owned_clusters.len() >= 2);

    let before_tree = read_all_files_from_clean_volume(&device.snapshot_durable_only());
    type Cut = (NtfsPersistenceStage, bool, Vec<u8>, Vec<u8>);
    let cuts: Arc<Mutex<Vec<Cut>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&cuts);
    let observed_device = Arc::clone(&device);
    let mut committed = false;
    engine.set_stage_hook(Some(Box::new(move |event| {
        committed |= event.stage == NtfsPersistenceStage::LogCommitBarrier;
        if matches!(
            event.stage,
            NtfsPersistenceStage::DirtyRestartBarrier
                | NtfsPersistenceStage::LogRecordWrite
                | NtfsPersistenceStage::LogCommitBarrier
                | NtfsPersistenceStage::TargetMetadataWrite
                | NtfsPersistenceStage::TargetMetadataBarrier
                | NtfsPersistenceStage::AckPublished
        ) {
            let mut snapshots = captured.lock().unwrap();
            if !snapshots
                .iter()
                .any(|(stage, _, _, _)| *stage == event.stage)
            {
                snapshots.push((
                    event.stage,
                    committed,
                    observed_device.snapshot_durable_only(),
                    observed_device.snapshot_reordered_pending(true),
                ));
            }
        }
        Ok(())
    })));
    let (removed, token) = engine.unlink_file(&cx, "/ARCHIVE").into_result().unwrap();
    engine.set_stage_hook(None);
    assert_eq!(removed, directory);
    assert!(token.matches_engine(&engine));
    let after_image = device.snapshot_durable_only();
    let after_tree = read_all_files_from_clean_volume(&after_image);
    assert!(after_tree.is_empty());
    let retired =
        NtfsFileRecord::parse(&after_image[record_offset..record_offset + RECORD_BYTES]).unwrap();
    assert!(!retired.in_use());
    assert_ne!(retired.sequence, directory.sequence);
    for cluster in owned_clusters {
        let byte = 74 * CLUSTER_BYTES + usize::try_from(cluster / 8).unwrap();
        assert_eq!(after_image[byte] & (1_u8 << (cluster % 8)), 0);
    }
    let snapshots = cuts.lock().unwrap();
    assert_eq!(snapshots.len(), 6);
    for (stage, committed, durable, reordered) in snapshots.iter() {
        assert_eq!(
            recover_crash_image_and_verify(durable),
            if *committed {
                &after_tree
            } else {
                &before_tree
            }
            .clone(),
            "directory removal durable prefix at {stage:?}"
        );
        let recovered = recover_crash_image_and_verify(reordered);
        if *committed {
            assert_eq!(
                recovered, after_tree,
                "committed directory removal at {stage:?}"
            );
        } else {
            assert!(recovered == before_tree || recovered == after_tree);
        }
    }
}

#[test]
fn unlink_directory_refuses_incomplete_or_provider_metadata_before_writes() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(512, 64, 0x7A11_C1C1_E000_0005);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let seed = FaultInjectingNtfsDevice::new(image);
    let mut seed_engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&seed) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    let (directory, _) = seed_engine.mkdir(&cx, "/", "empty").into_result().unwrap();
    let clean = seed.snapshot_durable_only();
    let offset = CLUSTER_BYTES + usize::try_from(directory.record).unwrap() * RECORD_BYTES;
    let original = copied_test_record_attributes(&clean[offset..offset + RECORD_BYTES]);
    for kind in [0x20_u32, 0x40, 0xC0, 0x100] {
        let device = FaultInjectingNtfsDevice::new(clean.clone());
        let mut engine = NtfsTransactionEngine::from_device(
            &cx,
            Arc::clone(&device) as Arc<dyn ByteDevice>,
            0,
            volume_bytes,
            write_options_clean(),
        )
        .unwrap();
        let mut attributes = original.clone();
        attributes.push(build_resident_attr(kind, 30, &[], false, &[0; 16]));
        attributes.sort_by_key(|attr| u32::from_le_bytes(attr[..4].try_into().unwrap()));
        let changed = build_file_record(
            directory.record as u32,
            directory.sequence,
            1,
            true,
            &attributes,
        );
        // Mutate after admission to exercise the per-operation refusal even if
        // an unsupported catalog becomes visible during this engine lifetime.
        device
            .write_all_at(&cx, ByteOffset(offset as u64), &changed)
            .unwrap();
        device.sync(&cx).unwrap();
        let before = device.snapshot_live();
        let writes = device.write_bytes_total();
        assert!(matches!(
            engine.unlink_file(&cx, "/empty"),
            NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
        ));
        assert_eq!(device.snapshot_live(), before);
        assert_eq!(device.write_bytes_total(), writes);
        assert!(engine.persistence_trace().is_empty());
    }
}

#[test]
fn directory_bplus_promotion_leaf_split_rename_and_unlink_consistency() {
    let cx = Cx::for_testing();
    let img = build_clean_ntfs_image(768, 64, 0x9988_7766_5544_3322);
    let vol_len = img.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(img);

    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .expect("open clean NTFS");

    engine.mkdir(&cx, "/", "bigdir").into_result().unwrap();
    engine.mkdir(&cx, "/", "outbox").into_result().unwrap();

    // Insert 38 long-named files to drive SMALL_INDEX -> LARGE_INDEX promotion + external INDX leaf splits!
    let mut expected: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    expected.insert("/bigdir/".to_owned(), Vec::new());
    expected.insert("/outbox/".to_owned(), Vec::new());
    for i in 0_u32..38 {
        let fname = format!("entry_{i:02}_extended_filename_for_indx_btree_split.txt");
        let payload = format!("payload-for-entry-{i:02}").into_bytes();
        engine
            .create_file(&cx, "/bigdir", &fname, &payload)
            .into_result()
            .unwrap();
        expected.insert(format!("/bigdir/{fname}"), payload);
    }

    // Verify case-insensitive $UpCase duplicate rejection!
    let dup = engine.create_file(
        &cx,
        "/bigdir",
        "ENTRY_00_EXTENDED_FILENAME_FOR_INDX_BTREE_SPLIT.TXT",
        b"dup",
    );
    assert!(matches!(dup, NtfsTxOutcome::NotCommitted(FfsError::Exists)));

    // Same-dir external-INDX rename + cross-dir rename + unlinks across leaves and root separator!
    let old5 = "/bigdir/entry_05_extended_filename_for_indx_btree_split.txt";
    let new5 = "/bigdir/zzz_renamed_05_in_external_indx.txt";
    engine
        .rename_entry(&cx, old5, new5, None)
        .into_result()
        .unwrap();
    let val5 = expected.remove(old5).unwrap();
    expected.insert(new5.to_owned(), val5);

    let old19 = "/bigdir/entry_19_extended_filename_for_indx_btree_split.txt";
    let out19 = "/outbox/moved_19.txt";
    engine
        .rename_entry(&cx, old19, out19, None)
        .into_result()
        .unwrap();
    let val19 = expected.remove(old19).unwrap();
    expected.insert(out19.to_owned(), val19);

    for victim in [0_u32, 12, 18, 20, 37] {
        let p = format!("/bigdir/entry_{victim:02}_extended_filename_for_indx_btree_split.txt");
        if expected.remove(&p).is_some() {
            engine.unlink_file(&cx, &p).into_result().unwrap();
        }
    }

    let actual = read_all_files_from_clean_volume(&dev.snapshot_live());
    assert_eq!(actual, expected);
}

#[test]
fn positioned_writes_and_truncation_preserve_bytes_and_native_consistency() {
    let cx = Cx::for_testing();
    let img = build_clean_ntfs_image(512, 64, 0x2345_6789);
    let vol_len = img.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(img);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .unwrap();
    let (reference, _) = engine
        .create_file(&cx, "/", "range.bin", b"abcdefghij")
        .into_result()
        .unwrap();

    let (updated, token) = engine
        .write_file_range(&cx, "/range.bin", 3, b"XYZ")
        .into_result()
        .unwrap();
    assert_eq!(updated, reference);
    assert!(token.matches_engine(&engine));
    assert_eq!(
        read_all_files_from_clean_volume(&dev.snapshot_durable_only())["/range.bin"],
        b"abcXYZghij"
    );
    assert!(
        engine
            .persistence_trace()
            .iter()
            .any(|event| event.operation == "write_file_range"
                && event.stage == NtfsPersistenceStage::AckPublished)
    );

    // A resident stream becomes nonresident, with a gap that must not contain
    // old bytes from the chosen free clusters.
    engine
        .write_file_range(&cx, "/RANGE.BIN", 20, &vec![0x4A; 5000])
        .into_result()
        .unwrap();
    let mut expected = b"abcXYZghij".to_vec();
    expected.resize(20, 0);
    expected.extend_from_slice(&vec![0x4A; 5000]);
    assert_eq!(
        read_all_files_from_clean_volume(&dev.snapshot_durable_only())["/range.bin"],
        expected
    );

    // Overwrite across a cluster boundary, retaining both sides of the range.
    engine
        .write_file_range(&cx, "/range.bin", 4093, b"boundary")
        .into_result()
        .unwrap();
    expected[4093..4101].copy_from_slice(b"boundary");
    assert_eq!(
        read_all_files_from_clean_volume(&dev.snapshot_durable_only())["/range.bin"],
        expected
    );

    engine
        .truncate_file(&cx, "/range.bin", 6)
        .into_result()
        .unwrap();
    expected.truncate(6);
    engine
        .truncate_file(&cx, "/range.bin", 8195)
        .into_result()
        .unwrap();
    expected.resize(8195, 0);
    assert_eq!(
        read_all_files_from_clean_volume(&dev.snapshot_durable_only())["/range.bin"],
        expected,
        "growth must not resurrect bytes discarded by shrink"
    );

    // A zero-byte write at an otherwise unrepresentable position is not growth.
    engine
        .write_file_range(&cx, "/range.bin", u64::MAX, b"")
        .into_result()
        .unwrap();
    assert_eq!(
        read_all_files_from_clean_volume(&dev.snapshot_durable_only())["/range.bin"],
        expected
    );
    engine
        .truncate_file(&cx, "/range.bin", 0)
        .into_result()
        .unwrap();
    assert!(
        read_all_files_from_clean_volume(&dev.snapshot_durable_only())["/range.bin"].is_empty()
    );
    engine.check_clean_consistency(&cx).unwrap();
    let reopened = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .unwrap();
    reopened.check_clean_consistency(&cx).unwrap();
}

#[test]
fn positioned_write_never_exposes_allocation_beyond_initialized_length() {
    let cx = Cx::for_testing();
    let img = build_clean_ntfs_image(512, 64, 0x5678_9ABC);
    let vol_len = img.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(img);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .unwrap();
    let (reference, _) = engine
        .create_file(&cx, "/", "initialized.bin", &vec![0xA6; 8192])
        .into_result()
        .unwrap();
    let mut image = dev.snapshot_durable_only();
    let mft_cluster = u64::from_le_bytes(image[0x30..0x38].try_into().unwrap());
    let record_at = usize::try_from(mft_cluster).unwrap() * CLUSTER_BYTES
        + usize::try_from(reference.record).unwrap() * RECORD_BYTES;
    let mut raw = restore_record(&image[record_at..record_at + RECORD_BYTES], b"FILE").unwrap();
    let mut at = usize::from(u16::from_le_bytes(raw[20..22].try_into().unwrap()));
    loop {
        let kind = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        assert_ne!(kind, u32::MAX, "fixture must contain an unnamed stream");
        if kind == DATA && raw[at + 9] == 0 {
            assert_eq!(raw[at + 8], 1, "fixture stream must be nonresident");
            raw[at + 56..at + 64].copy_from_slice(&5_u64.to_le_bytes());
            break;
        }
        at += u32::from_le_bytes(raw[at + 4..at + 8].try_into().unwrap()) as usize;
    }
    image[record_at..record_at + RECORD_BYTES].copy_from_slice(&protect_record_bytes(raw, 0x4826));
    let initialized_dev = FaultInjectingNtfsDevice::new(image);
    let mut initialized_engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&initialized_dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .unwrap();
    initialized_engine
        .write_file_range(&cx, "/initialized.bin", 10, b"edit")
        .into_result()
        .unwrap();
    let mut expected = vec![0_u8; 8192];
    expected[..5].fill(0xA6);
    expected[10..14].copy_from_slice(b"edit");
    assert_eq!(
        read_all_files_from_clean_volume(&initialized_dev.snapshot_durable_only())["/initialized.bin"],
        expected,
        "uninitialized physical bytes must remain logically zero"
    );
}

#[test]
fn range_and_truncate_limits_refuse_before_any_backing_write() {
    let cx = Cx::for_testing();
    let img = build_clean_ntfs_image(512, 64, 0x3456_789A);
    let vol_len = img.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(img);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .unwrap();
    engine
        .create_file(&cx, "/", "keep.bin", b"preserve me")
        .into_result()
        .unwrap();
    let before = dev.snapshot_live();
    let writes = dev.write_bytes_total();
    let max_size = ffs_ntfs::transaction::MAX_FILE_EDIT_BYTES;
    for outcome in [
        engine.write_file_range(&cx, "/keep.bin", u64::MAX, b"xx"),
        engine.write_file_range(&cx, "/keep.bin", max_size, b"x"),
        engine.truncate_file(&cx, "/keep.bin", max_size + 1),
        engine.truncate_file(&cx, "/keep.bin", u64::MAX),
    ] {
        let NtfsTxOutcome::NotCommitted(error) = outcome else {
            panic!("oversized edit must be rejected before publication");
        };
        assert_eq!(error.to_errno(), libc::EFBIG);
    }
    assert!(matches!(
        engine.write_file_range(&cx, "/missing", 0, b"x"),
        NtfsTxOutcome::NotCommitted(FfsError::NotFound(_))
    ));
    assert!(matches!(
        engine.truncate_file(&cx, "/", 0),
        NtfsTxOutcome::NotCommitted(FfsError::IsDirectory)
    ));
    assert_eq!(dev.write_bytes_total(), writes);
    assert_eq!(dev.snapshot_live(), before);
}

#[test]
fn range_and_truncate_crash_cuts_recover_only_the_acknowledged_prefix() {
    let cx = Cx::for_testing();
    let img = build_clean_ntfs_image(512, 64, 0x4567_89AB);
    let vol_len = img.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(img);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .unwrap();
    engine
        .create_file(&cx, "/", "range.bin", &vec![0x35; 4500])
        .into_result()
        .unwrap();

    // Covers COW positioned growth, nonresident shrink, zero-extension, and
    // complete reclamation. Every observation is reopened by a new engine.
    for (size, range) in [(9000, true), (700, false), (6000, false), (0, false)] {
        let before = read_all_files_from_clean_volume(&dev.snapshot_durable_only());
        type Cut = (NtfsPersistenceStage, bool, Vec<u8>, Vec<u8>);
        let cuts: Arc<Mutex<Vec<Cut>>> = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&cuts);
        let device = Arc::clone(&dev);
        let mut committed = false;
        engine.set_stage_hook(Some(Box::new(move |event| {
            committed |= event.stage == NtfsPersistenceStage::LogCommitBarrier;
            captured.lock().unwrap().push((
                event.stage,
                committed,
                device.snapshot_durable_only(),
                device.snapshot_reordered_pending(true),
            ));
            Ok(())
        })));
        let outcome = if range {
            engine.write_file_range(&cx, "/range.bin", size, b"persisted-range")
        } else {
            engine.truncate_file(&cx, "/range.bin", size)
        };
        outcome.into_result().unwrap();
        engine.set_stage_hook(None);
        let after = read_all_files_from_clean_volume(&dev.snapshot_durable_only());
        let captured = cuts.lock().unwrap();
        assert!(captured.iter().any(|(_, committed, _, _)| !committed));
        assert!(captured.iter().any(|(_, committed, _, _)| *committed));
        for (stage, committed, durable, reordered) in captured.iter() {
            assert_eq!(
                recover_crash_image_and_verify(durable),
                if *committed { &after } else { &before }.clone(),
                "durable prefix at {stage:?}, size={size}, range={range}"
            );
            let recovered = recover_crash_image_and_verify(reordered);
            if *committed {
                assert_eq!(recovered, after, "acknowledged journal prefix at {stage:?}");
            } else {
                assert!(
                    recovered == before || recovered == after,
                    "partial pending writes at {stage:?} must not expose mixed content"
                );
            }
        }
    }
}

#[test]
fn persistence_prefix_fault_cuts_and_write_reordering_across_all_stages() {
    let cx = Cx::for_testing();
    let img = build_clean_ntfs_image(512, 64, 0xA1B2_C3D4_E5F6_0718);
    let vol_len = img.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(img);

    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .unwrap();

    // Establish baseline acknowledged prefix state S0.
    engine.mkdir(&cx, "/", "work").into_result().unwrap();
    engine
        .create_file(&cx, "/work", "keep.txt", b"baseline-committed")
        .into_result()
        .unwrap();
    let s0 = read_all_files_from_clean_volume(&dev.snapshot_live());

    // Capture crash snapshots at every persistence stage of a multi-cluster COW create_file,
    // a resident write_file_data, a cross-dir rename, and an unlink!
    #[derive(Clone)]
    struct CutCapture {
        stage: NtfsPersistenceStage,
        after_commit_barrier: bool,
        live: Vec<u8>,
        durable_only: Vec<u8>,
        reordered: Vec<u8>,
    }

    let cuts: Arc<Mutex<Vec<CutCapture>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_commit: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    {
        let cuts_ref = Arc::clone(&cuts);
        let dev_ref = Arc::clone(&dev);
        let commit_ref = Arc::clone(&seen_commit);
        engine.set_stage_hook(Some(Box::new(move |ev| {
            if ev.stage == NtfsPersistenceStage::LogCommitBarrier {
                *commit_ref.lock().unwrap() = true;
            }
            let after_commit = *commit_ref.lock().unwrap();
            cuts_ref.lock().unwrap().push(CutCapture {
                stage: ev.stage,
                after_commit_barrier: after_commit,
                live: dev_ref.snapshot_live(),
                durable_only: dev_ref.snapshot_durable_only(),
                reordered: dev_ref.snapshot_reordered_pending(true),
            });
            Ok(())
        })));
    }

    let big_payload = vec![0x42_u8; 8_700];
    engine
        .create_file(&cx, "/work", "staged_big.bin", &big_payload)
        .into_result()
        .unwrap();
    engine.set_stage_hook(None);
    let s1 = read_all_files_from_clean_volume(&dev.snapshot_live());

    let captured = cuts.lock().unwrap().clone();
    assert!(
        captured.len() >= 8,
        "expected rich stage trace, got {}",
        captured.len()
    );

    let mut saw_pre_commit_loser = false;
    let mut saw_post_commit_winner = false;
    for cut in &captured {
        // 1. Durable-only cut (all un-synced writes lost):
        let tree_durable = recover_crash_image_and_verify(&cut.durable_only);
        if cut.after_commit_barrier {
            saw_post_commit_winner = true;
            assert_eq!(
                tree_durable, s1,
                "after LogCommitBarrier at {:?}, Winner Redo must preserve S1",
                cut.stage
            );
        } else {
            assert_eq!(
                tree_durable, s0,
                "before LogCommitBarrier at {:?}, durable-only cut must equal S0",
                cut.stage
            );
        }

        // 2. Live cut (including un-synced pre-commit RCRD writes -> Active Loser Undo!):
        let tree_live = recover_crash_image_and_verify(&cut.live);
        if !cut.after_commit_barrier && cut.stage == NtfsPersistenceStage::LogRecordWrite {
            saw_pre_commit_loser = true;
        }
        if cut.after_commit_barrier {
            assert_eq!(tree_live, s1);
        } else {
            // Note: the second LogRecordWrite in Stage 4b writes CommitTransaction before LogCommitBarrier;
            // if CommitTransaction reached disk, ARIES treats it as a Winner (valid prefix S1), otherwise S0!
            assert!(
                tree_live == s0 || tree_live == s1,
                "live cut at {:?} produced non-prefix state",
                cut.stage
            );
        }

        // 3. Reordered out-of-order pending writes between sync() barriers:
        let tree_reordered = recover_crash_image_and_verify(&cut.reordered);
        assert!(
            tree_reordered == s0 || tree_reordered == s1,
            "reordered pending cut at {:?} violated prefix consistency",
            cut.stage
        );
    }
    assert!(saw_pre_commit_loser);
    assert!(saw_post_commit_winner);

    // Also verify volatile read-only NtfsVolume (--recover-logfile) on a resident user-file Winner cut!
    type StageSnapshot = (NtfsPersistenceStage, Vec<u8>);
    let resident_cuts: Arc<Mutex<Vec<StageSnapshot>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let rc = Arc::clone(&resident_cuts);
        let d = Arc::clone(&dev);
        engine.set_stage_hook(Some(Box::new(move |ev| {
            if ev.stage == NtfsPersistenceStage::LogCommitBarrier {
                rc.lock().unwrap().push((ev.stage, d.snapshot_live()));
            }
            Ok(())
        })));
    }
    engine
        .write_file_data(&cx, "/work/keep.txt", b"volatile-redo-verified!")
        .into_result()
        .unwrap();
    engine.set_stage_hook(None);

    let (_, winner_before_target_img) = resident_cuts.lock().unwrap().pop().unwrap();
    // On winner_before_target_img, $MFT still has "baseline-committed", while $LogFile has CommitTransaction!
    let ro_dev = FaultInjectingNtfsDevice::new(winner_before_target_img);
    let ro_vol =
        NtfsVolume::from_device_with_options(&cx, Box::new(ArcDevice(ro_dev)), 0, vol_len, true)
            .expect("NtfsVolume volatile --recover-logfile");
    assert!(ro_vol.logfile_recovery.is_some());
    let root_ro = ro_vol.record(&cx, 5, Some(5)).unwrap();
    let work_entry = ro_vol
        .list_directory(&cx, &root_ro)
        .unwrap()
        .into_iter()
        .find(|e| String::from_utf16(&e.filename.name).unwrap() == "work")
        .unwrap();
    let work_rec = ro_vol
        .record(
            &cx,
            work_entry.reference.record,
            Some(work_entry.reference.sequence),
        )
        .unwrap();
    let keep_entry = ro_vol
        .list_directory(&cx, &work_rec)
        .unwrap()
        .into_iter()
        .find(|e| String::from_utf16(&e.filename.name).unwrap() == "keep.txt")
        .unwrap();
    let keep_rec = ro_vol
        .record(
            &cx,
            keep_entry.reference.record,
            Some(keep_entry.reference.sequence),
        )
        .unwrap();
    let keep_stream = ro_vol.data_stream(&cx, &keep_rec, &[]).unwrap();
    let keep_bytes = ro_vol.read(&cx, &keep_stream, 0, 64).unwrap();
    assert_eq!(keep_bytes, b"volatile-redo-verified!");
}

#[test]
fn interleaved_winner_and_loser_in_logfile_plus_recovery_crash_idempotency() {
    let cx = Cx::for_testing();
    let img = build_clean_ntfs_image(512, 64, 0x55AA_1234_9876_CAFE);
    let vol_len = img.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(img);

    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .unwrap();

    let (f1_ref, _) = engine
        .create_file(&cx, "/", "winner.txt", b"v0-winner")
        .into_result()
        .unwrap();
    let (f2_ref, _) = engine
        .create_file(&cx, "/", "loser.txt", b"v0-loser")
        .into_result()
        .unwrap();

    // Capture a clean base disk snapshot where winner="v0-winner" and loser="v0-loser".
    let base_disk = dev.snapshot_live();

    // Locate the unnamed DATA resident value offset inside f1 and f2 FILE records (LCN 1 = byte 4096).
    let find_resident_data_offsets = |rec_no: u64| -> (u16, u16, Vec<u8>) {
        let off = CLUSTER_BYTES + usize::try_from(rec_no).unwrap() * RECORD_BYTES;
        let restored = restore_record(&base_disk[off..off + RECORD_BYTES], b"FILE").unwrap();
        let mut pos = usize::from(u16::from_le_bytes([restored[20], restored[21]]));
        while pos + 8 <= restored.len() {
            let kind = u32::from_le_bytes(restored[pos..pos + 4].try_into().unwrap());
            if kind == u32::MAX {
                break;
            }
            let sz = u32::from_le_bytes(restored[pos + 4..pos + 8].try_into().unwrap()) as usize;
            if kind == DATA && restored[pos + 9] == 0 {
                let voff =
                    usize::from(u16::from_le_bytes([restored[pos + 20], restored[pos + 21]]));
                let vlen =
                    u32::from_le_bytes(restored[pos + 16..pos + 20].try_into().unwrap()) as usize;
                return (
                    u16::try_from(pos).unwrap(),
                    u16::try_from(voff).unwrap(),
                    restored[pos + voff..pos + voff + vlen].to_vec(),
                );
            }
            pos += sz;
        }
        panic!("missing resident DATA");
    };

    let (f1_rec_off, f1_val_off, f1_old) = find_resident_data_offsets(f1_ref.record);
    let (f2_rec_off, f2_val_off, f2_old) = find_resident_data_offsets(f2_ref.record);
    assert_eq!(f1_old, b"v0-winner");
    assert_eq!(f2_old, b"v0-loser");

    // Build an interleaved dirty $LogFile on top of `base_disk`:
    // - tx_1 (slot 24): updates winner.txt ("v0-winner" -> "v1-winner") AND COMMITS (0x1A),
    //   WITHOUT writing target FILE record to disk (NO-FORCE)!
    // - tx_2 (slot 64): updates loser.txt ("v0-loser" -> "XX-LOSER") WITHOUT committing!
    let mut dirty_disk = base_disk;
    let log_bytes = 64_u64 * (CLUSTER_BYTES as u64);
    let mut ring =
        NtfsLogRingWriter::new_fresh(CLUSTER_BYTES as u32, (2, 0), log_bytes, 1, 1).unwrap();

    // OpenNonresidentAttribute (0x15) for $MFT::$DATA at slot 24.
    let open_mft_spec = NtfsClientUpdateSpec {
        redo_op: NtfsLogOp::OpenNonresidentAttribute,
        undo_op: NtfsLogOp::Noop,
        target_attribute: 24,
        record_offset: 0,
        attribute_offset: 0,
        cluster_block_offset: 0,
        target_vcn: 0,
        target_lcns: Vec::new(),
        redo_data: ffs_ondisk::ntfs::logfile_writer::encode_open_attribute_entry(
            DATA,
            0,
            NtfsReference {
                record: 0,
                sequence: 1,
            }
            .encode()
            .unwrap(),
            0,
        )
        .to_vec(),
        undo_data: Vec::new(),
    };
    let tx1_id = 24_u32;
    let tx2_id = 64_u32;

    let r_open = ring
        .append_raw_record(
            LFS_RECORD_CLIENT,
            tx1_id,
            0,
            0,
            &encode_client_update_payload(&open_mft_spec).unwrap(),
        )
        .unwrap();

    let winner_vcn = (f1_ref.record * (RECORD_BYTES as u64)) / (CLUSTER_BYTES as u64);
    let winner_cbo = u16::try_from(
        ((f1_ref.record * (RECORD_BYTES as u64)) % (CLUSTER_BYTES as u64)) / (SECTOR_BYTES as u64),
    )
    .unwrap();
    let winner_phys_cluster = 1 + winner_vcn;

    let loser_vcn = (f2_ref.record * (RECORD_BYTES as u64)) / (CLUSTER_BYTES as u64);
    let loser_cbo = u16::try_from(
        ((f2_ref.record * (RECORD_BYTES as u64)) % (CLUSTER_BYTES as u64)) / (SECTOR_BYTES as u64),
    )
    .unwrap();
    let loser_phys_cluster = 1 + loser_vcn;

    let r_tx1_upd = ring
        .append_raw_record(
            LFS_RECORD_CLIENT,
            tx1_id,
            r_open.lsn,
            0,
            &encode_client_update_payload(&NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::UpdateResidentValue,
                undo_op: NtfsLogOp::UpdateResidentValue,
                target_attribute: 24,
                record_offset: f1_rec_off,
                attribute_offset: f1_val_off,
                cluster_block_offset: winner_cbo,
                target_vcn: winner_vcn,
                target_lcns: vec![winner_phys_cluster],
                redo_data: b"v1-winner".to_vec(),
                undo_data: b"v0-winner".to_vec(),
            })
            .unwrap(),
        )
        .unwrap();

    // Interleave tx2 BEFORE tx1 commits!
    let r_tx2_upd = ring
        .append_raw_record(
            LFS_RECORD_CLIENT,
            tx2_id,
            0,
            0,
            &encode_client_update_payload(&NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::UpdateResidentValue,
                undo_op: NtfsLogOp::UpdateResidentValue,
                target_attribute: 24,
                record_offset: f2_rec_off,
                attribute_offset: f2_val_off,
                cluster_block_offset: loser_cbo,
                target_vcn: loser_vcn,
                target_lcns: vec![loser_phys_cluster],
                redo_data: b"XX-LOSER".to_vec(),
                undo_data: b"v0-loser".to_vec(),
            })
            .unwrap(),
        )
        .unwrap();

    // Commit tx1 ONLY (tx2 remains an Active Loser)!
    let r_tx1_commit = ring
        .append_raw_record(
            LFS_RECORD_CLIENT,
            tx1_id,
            r_tx1_upd.lsn,
            r_tx1_upd.lsn,
            &encode_client_update_payload(&NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::CommitTransaction,
                undo_op: NtfsLogOp::Noop,
                target_attribute: 0,
                record_offset: 0,
                attribute_offset: 0,
                cluster_block_offset: 0,
                target_vcn: 0,
                target_lcns: Vec::new(),
                redo_data: Vec::new(),
                undo_data: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();

    let log_phys_base = 10 * CLUSTER_BYTES;
    for rec in [&r_open, &r_tx1_upd, &r_tx2_upd, &r_tx1_commit] {
        let p = log_phys_base + usize::try_from(rec.page_vbo).unwrap();
        dirty_disk[p..p + CLUSTER_BYTES].copy_from_slice(&rec.protected_page);
    }
    // Write dirty RSTR pages (clean=false) to both slots 0 and 1!
    for _ in 0..2 {
        let rstr_page = ring.build_next_rstr_page(false).unwrap();
        let p = log_phys_base + usize::try_from(rstr_page.page_vbo).unwrap();
        dirty_disk[p..p + CLUSTER_BYTES].copy_from_slice(&rstr_page.bytes);
    }

    // First prove mid-recovery crash idempotency: abort `recover_in_place` right after
    // its first TargetMetadataWrite (when CLRs are durable in $LogFile and target pages
    // are only partially written) and verify a second fresh recovery converges cleanly!
    {
        let crash_mid_rec_dev = FaultInjectingNtfsDevice::new(dirty_disk.clone());
        // Open without auto-recovery is refused; instead open clean image first? No:
        // capture via a wrapper device that fails after N writes during from_device(recover_dirty=true)!
        struct AbortAfterTargetWrite {
            inner: Arc<FaultInjectingNtfsDevice>,
            seen_syncs: Mutex<usize>,
            writes_after_clr_sync: Mutex<usize>,
        }
        impl ByteDevice for AbortAfterTargetWrite {
            fn len_bytes(&self) -> u64 {
                self.inner.len_bytes()
            }
            fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
                self.inner.read_exact_at(cx, offset, buf)
            }
            fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
                if *self.seen_syncs.lock().unwrap() >= 1 {
                    let mut w = self.writes_after_clr_sync.lock().unwrap();
                    *w += 1;
                    if *w == 2 {
                        return Err(FfsError::Io(std::io::Error::other(
                            "mid-recovery crash during TargetMetadataWrite",
                        )));
                    }
                }
                self.inner.write_all_at(cx, offset, buf)
            }
            fn sync(&self, cx: &Cx) -> Result<()> {
                let res = self.inner.sync(cx);
                if res.is_ok() {
                    *self.seen_syncs.lock().unwrap() += 1;
                }
                res
            }
        }

        let abort_dev = Arc::new(AbortAfterTargetWrite {
            inner: Arc::clone(&crash_mid_rec_dev),
            seen_syncs: Mutex::new(0),
            writes_after_clr_sync: Mutex::new(0),
        });
        let aborted = NtfsTransactionEngine::from_device(
            &cx,
            abort_dev as Arc<dyn ByteDevice>,
            0,
            vol_len,
            write_options_recover(),
        );
        assert!(
            aborted.is_err(),
            "mid-recovery fault must abort first recovery"
        );

        // Now recover the half-recovered image a second time!
        let second_tree = recover_crash_image_and_verify(&crash_mid_rec_dev.snapshot_live());
        assert_eq!(
            second_tree.get("/winner.txt").map(Vec::as_slice),
            Some(b"v1-winner".as_slice())
        );
        assert_eq!(
            second_tree.get("/loser.txt").map(Vec::as_slice),
            Some(b"v0-loser".as_slice())
        );
    }

    // Now run full persistent ARIES recovery cleanly and inspect summary counters!
    let rec_dev = FaultInjectingNtfsDevice::new(dirty_disk);
    let mut rec_engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&rec_dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_recover(),
    )
    .expect("recover interleaved winner + loser");

    let summary = rec_engine.last_recovery().expect("recovery ran").clone();
    assert!(summary.was_dirty);
    assert_eq!(summary.committed_winners, vec![tx1_id]);
    assert_eq!(summary.undone_losers, vec![tx2_id]);
    assert!(summary.redo_applied >= 1);
    assert_eq!(summary.undo_applied, 1);
    assert_eq!(summary.clr_written, 1);

    let recovered_tree = read_all_files_from_clean_volume(&rec_dev.snapshot_live());
    assert_eq!(
        recovered_tree.get("/winner.txt").map(Vec::as_slice),
        Some(b"v1-winner".as_slice())
    );
    assert_eq!(
        recovered_tree.get("/loser.txt").map(Vec::as_slice),
        Some(b"v0-loser".as_slice())
    );

    // Re-running recover_in_place on an already-clean volume is a clean no-op!
    let noop = rec_engine.recover_in_place(&cx).unwrap();
    assert!(!noop.was_dirty);
}

#[test]
fn torn_rstr_single_slot_heals_while_dual_rstr_or_rcrd_torn_refuses_without_writes() {
    let cx = Cx::for_testing();
    let img = build_clean_ntfs_image(512, 64, 0xDEAD_BEEF_CAFE_BABE);
    let vol_len = img.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(img);

    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .unwrap();
    engine
        .create_file(&cx, "/", "intact.txt", b"healed-after-torn-rstr")
        .into_result()
        .unwrap();
    let clean_after_tx = dev.snapshot_live();
    let log_phys_base = 10 * CLUSTER_BYTES;

    // 1. Tear RSTR slot 0 sector trailer while slot 1 remains valid -> recovers & heals slot 0!
    {
        let mut slot0_torn = clean_after_tx.clone();
        slot0_torn[log_phys_base + 510] ^= 0xFF;
        let d0 = FaultInjectingNtfsDevice::new(slot0_torn);
        // Without recover_dirty, opening refuses without writing!
        let err = NtfsTransactionEngine::from_device(
            &cx,
            Arc::clone(&d0) as Arc<dyn ByteDevice>,
            0,
            vol_len,
            write_options_clean(),
        );
        assert!(err.is_err());
        assert_eq!(d0.write_bytes_total(), 0);

        // With recover_dirty=true, heals slot 0!
        let eng0 = NtfsTransactionEngine::from_device(
            &cx,
            Arc::clone(&d0) as Arc<dyn ByteDevice>,
            0,
            vol_len,
            write_options_recover(),
        )
        .expect("heal torn RSTR slot 0");
        assert_eq!(eng0.last_recovery().unwrap().healed_torn_rstr_slot, Some(0));
        let tree = read_all_files_from_clean_volume(&d0.snapshot_live());
        assert_eq!(
            tree.get("/intact.txt").map(Vec::as_slice),
            Some(b"healed-after-torn-rstr".as_slice())
        );
    }

    // 2. Tear BOTH RSTR slot 0 and slot 1 -> refuses fail-closed with ZERO bytes written!
    {
        let mut both_torn = clean_after_tx.clone();
        both_torn[log_phys_base + 510] ^= 0xFF;
        both_torn[log_phys_base + CLUSTER_BYTES + 510] ^= 0xFF;
        let dboth = FaultInjectingNtfsDevice::new(both_torn);
        let res = NtfsTransactionEngine::from_device(
            &cx,
            Arc::clone(&dboth) as Arc<dyn ByteDevice>,
            0,
            vol_len,
            write_options_recover(),
        );
        assert!(res.is_err());
        assert_eq!(dboth.write_bytes_total(), 0);
    }

    // 3. Torn RCRD sector in dirty log window -> refuses fail-closed with ZERO bytes written!
    {
        let mut rcrd_torn = clean_after_tx;
        // Mark RSTR dirty (open_log_count=1, flags=0) and tear first ring RCRD page (page 34)!
        let rstr_dirty = NtfsRestartConfig {
            page_size: CLUSTER_BYTES as u32,
            version: (2, 0),
            file_size: 64 * (CLUSTER_BYTES as u64),
            client_seq: 1,
            clean: false,
            open_log_count: 1,
            oldest_lsn: 1 << 9,
            client_restart_lsn: 0,
            current_lsn: 1 << 9,
            last_lsn_data_len: 88,
            usa_token: 0x3333,
        };
        let p_rstr = ffs_ondisk::ntfs::logfile_writer::encode_rstr_page(&rstr_dirty).unwrap();
        rcrd_torn[log_phys_base..log_phys_base + CLUSTER_BYTES].copy_from_slice(&p_rstr);
        rcrd_torn[log_phys_base + CLUSTER_BYTES..log_phys_base + 2 * CLUSTER_BYTES]
            .copy_from_slice(&p_rstr);
        // Tear sector trailer in ring page 34:
        rcrd_torn[log_phys_base + 34 * CLUSTER_BYTES + 510] ^= 0xAA;

        let drcrd = FaultInjectingNtfsDevice::new(rcrd_torn);
        let res = NtfsTransactionEngine::from_device(
            &cx,
            Arc::clone(&drcrd) as Arc<dyn ByteDevice>,
            0,
            vol_len,
            write_options_recover(),
        );
        assert!(res.is_err());
        assert_eq!(drcrd.write_bytes_total(), 0);
    }
}

#[test]
fn logfile_ring_wrap_enospc_sync_failure_outcomes_and_idempotent_rename_retry() {
    let cx = Cx::for_testing();
    // Tight 52-page $LogFile and only 8 free data clusters (total_clusters = 11 + 52 + 32 + 8 = 103)!
    let img = build_clean_ntfs_image(103, 52, 0x0102_0304_0506_0708);
    let vol_len = img.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(img);

    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .unwrap();

    let (f_ref, first_tok) = engine
        .create_file(&cx, "/", "counter.txt", b"iter-000")
        .into_result()
        .unwrap();

    // 1. Run 80 resident updates to wrap the 18-ring-page (52 - 34 = 18) $LogFile multiple times!
    let mut last_tok = first_tok;
    for i in 1_u32..=80 {
        let payload = format!("iter-{i:03}").into_bytes();
        let (_, tok) = engine
            .write_file_data(&cx, "/counter.txt", &payload)
            .into_result()
            .unwrap();
        assert!(tok.commit_lsn() > last_tok.commit_lsn());
        last_tok = tok;
    }

    // 2. Request a 20-cluster file on a volume with only 8 free clusters -> NotCommitted(NoSpace)!
    let enospc = engine.create_file(&cx, "/", "too_big.bin", &vec![0x99; 20 * CLUSTER_BYTES]);
    assert!(matches!(
        enospc,
        NtfsTxOutcome::NotCommitted(FfsError::NoSpace)
    ));
    let tree_after_enospc = read_all_files_from_clean_volume(&dev.snapshot_live());
    assert_eq!(
        tree_after_enospc.get("/counter.txt").map(Vec::as_slice),
        Some(b"iter-080".as_slice())
    );
    assert!(!tree_after_enospc.contains_key("/too_big.bin"));

    // 3. Inject ByteDevice::sync() failure on 1st barrier (DirtyRestartBarrier -> before commit):
    //    MUST return NotCommitted, NEVER Committed!
    dev.set_fail_sync_call(Some(1));
    let pre_sync_fail = engine.write_file_data(&cx, "/counter.txt", b"sync-fail-1");
    assert!(matches!(pre_sync_fail, NtfsTxOutcome::NotCommitted(_)));
    dev.set_fail_sync_call(None);

    // Recover and reopen cleanly before testing post-commit sync failure:
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_recover(),
    )
    .unwrap();

    // 4. Inject ByteDevice::sync() failure on 2nd barrier (LogCommitBarrier -> at/after commit write):
    //    MUST return Uncertain, NEVER Committed!
    dev.set_fail_sync_call(Some(2));
    let commit_sync_fail = engine.write_file_data(&cx, "/counter.txt", b"sync-fail-2");
    assert!(matches!(commit_sync_fail, NtfsTxOutcome::Uncertain { .. }));
    dev.set_fail_sync_call(None);

    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_recover(),
    )
    .unwrap();

    // 5. Simulate post-commit pre-reply cancellation on rename_entry (at CleanRestartSlotABarrier) ->
    //    returns Uncertain, then idempotent retry with expected_source_ref succeeds cleanly!
    engine.set_stage_hook(Some(Box::new(|ev| {
        if ev.stage == NtfsPersistenceStage::CleanRestartSlotABarrier {
            return Err(FfsError::Cancelled);
        }
        Ok(())
    })));
    let cancel_out = engine.rename_entry(&cx, "/counter.txt", "/renamed_counter.txt", Some(f_ref));
    assert!(matches!(
        cancel_out,
        NtfsTxOutcome::Uncertain {
            reason: FfsError::Cancelled,
            ..
        }
    ));
    engine.set_stage_hook(None);

    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_recover(),
    )
    .unwrap();
    let (retry_ref, retry_tok) = engine
        .rename_entry(&cx, "/counter.txt", "/renamed_counter.txt", Some(f_ref))
        .into_result()
        .expect("idempotent post-commit rename retry");
    assert_eq!(retry_ref, f_ref);
    assert!(retry_tok.matches_engine(&engine));

    let final_tree = read_all_files_from_clean_volume(&dev.snapshot_live());
    assert!(final_tree.contains_key("/renamed_counter.txt"));
    assert!(!final_tree.contains_key("/counter.txt"));
}

#[test]
fn negative_controls_refuse_hibernation_unknown_opcode_prepared_tx_and_foreign_token() {
    let cx = Cx::for_testing();
    let img_a = build_clean_ntfs_image(512, 64, 0xAAAA_BBBB_CCCC_DDDD);
    let img_b = build_clean_ntfs_image(512, 64, 0xEEEE_FFFF_1111_2222);
    let vol_len = img_a.len() as u64 - SECTOR_BYTES as u64;

    // 1. Cross-storage NtfsDurableToken rejection:
    let dev_a = FaultInjectingNtfsDevice::new(img_a);
    let dev_b = FaultInjectingNtfsDevice::new(img_b);
    let mut eng_a = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev_a) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .unwrap();
    let eng_b = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev_b) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_clean(),
    )
    .unwrap();
    let (_, tok_a) = eng_a
        .create_file(&cx, "/", "a.txt", b"from-a")
        .into_result()
        .unwrap();
    assert!(tok_a.matches_engine(&eng_a));
    assert!(!tok_a.matches_engine(&eng_b));

    // 2. Missing explicit write flags -> PermissionDenied with zero bytes written!
    let ro_try = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev_b) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        NtfsWriteOptions {
            offline_image: true,
            allow_write: false,
            recover_dirty: false,
        },
    );
    assert!(matches!(ro_try, Err(FfsError::PermissionDenied)));
    assert_eq!(dev_b.write_bytes_total(), 0);

    // 3. Active Windows Hibernation / Fast Startup (`hiberfil.sys` in root with non-zero header) ->
    //    refused fail-closed on subsequent open with ZERO bytes written!
    eng_a
        .create_file(&cx, "/", "hiberfil.sys", b"HIBR-ACTIVE-HEADER-IMAGE")
        .into_result()
        .unwrap();
    let hiber_img = dev_a.snapshot_live();
    let dev_hiber = FaultInjectingNtfsDevice::new(hiber_img);
    let hiber_open = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev_hiber) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_recover(),
    );
    assert!(matches!(hiber_open, Err(FfsError::UnsupportedFeature(_))));
    assert_eq!(dev_hiber.write_bytes_total(), 0);

    // 4. In-doubt Prepared transaction (0x19) in dirty $LogFile -> refused with ZERO bytes written!
    let clean_b = dev_b.snapshot_live();
    let mut prepared_img = clean_b.clone();
    let mut ring = NtfsLogRingWriter::new_fresh(
        CLUSTER_BYTES as u32,
        (2, 0),
        64 * CLUSTER_BYTES as u64,
        1,
        1,
    )
    .unwrap();
    let prep_rec = ring
        .append_raw_record(
            LFS_RECORD_CLIENT,
            24,
            0,
            0,
            &encode_client_update_payload(&NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::PrepareTransaction,
                undo_op: NtfsLogOp::Noop,
                target_attribute: 0,
                record_offset: 0,
                attribute_offset: 0,
                cluster_block_offset: 0,
                target_vcn: 0,
                target_lcns: Vec::new(),
                redo_data: Vec::new(),
                undo_data: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();
    let log_phys = 10 * CLUSTER_BYTES;
    let p_off = log_phys + usize::try_from(prep_rec.page_vbo).unwrap();
    prepared_img[p_off..p_off + CLUSTER_BYTES].copy_from_slice(&prep_rec.protected_page);
    for _ in 0..2 {
        let rstr = ring.build_next_rstr_page(false).unwrap();
        let at = log_phys + usize::try_from(rstr.page_vbo).unwrap();
        prepared_img[at..at + CLUSTER_BYTES].copy_from_slice(&rstr.bytes);
    }
    let dev_prep = FaultInjectingNtfsDevice::new(prepared_img);
    let prepared_open_outcome = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev_prep) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_recover(),
    );
    assert!(matches!(
        prepared_open_outcome,
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(dev_prep.write_bytes_total(), 0);

    // 5. Unknown $LogFile opcode (0xFE) in dirty $LogFile -> refused with ZERO bytes written!
    let mut unk_img = clean_b;
    let mut ring_unk = NtfsLogRingWriter::new_fresh(
        CLUSTER_BYTES as u32,
        (2, 0),
        64 * CLUSTER_BYTES as u64,
        1,
        1,
    )
    .unwrap();
    let mut raw_unk_payload = vec![0_u8; 40];
    raw_unk_payload[0..2].copy_from_slice(&0x00FE_u16.to_le_bytes()); // unknown redo op!
    raw_unk_payload[2..4].copy_from_slice(&0x0000_u16.to_le_bytes());
    let unk_rec = ring_unk
        .append_raw_record(LFS_RECORD_CLIENT, 24, 0, 0, &raw_unk_payload)
        .unwrap();
    let u_off = log_phys + usize::try_from(unk_rec.page_vbo).unwrap();
    unk_img[u_off..u_off + CLUSTER_BYTES].copy_from_slice(&unk_rec.protected_page);
    for _ in 0..2 {
        let rstr = ring_unk.build_next_rstr_page(false).unwrap();
        let at = log_phys + usize::try_from(rstr.page_vbo).unwrap();
        unk_img[at..at + CLUSTER_BYTES].copy_from_slice(&rstr.bytes);
    }
    let dev_unk = FaultInjectingNtfsDevice::new(unk_img);
    let unknown_opcode_outcome = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&dev_unk) as Arc<dyn ByteDevice>,
        0,
        vol_len,
        write_options_recover(),
    );
    assert!(matches!(
        unknown_opcode_outcome,
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(dev_unk.write_bytes_total(), 0);
}

fn copied_test_record_attributes(raw: &[u8]) -> Vec<Vec<u8>> {
    let restored = restore_record(raw, b"FILE").unwrap();
    let mut at = usize::from(u16::from_le_bytes([restored[20], restored[21]]));
    let mut attributes = Vec::new();
    loop {
        let kind = u32::from_le_bytes(restored[at..at + 4].try_into().unwrap());
        if kind == u32::MAX {
            return attributes;
        }
        let bytes = u32::from_le_bytes(restored[at + 4..at + 8].try_into().unwrap()) as usize;
        attributes.push(restored[at..at + bytes].to_vec());
        at += bytes;
    }
}

#[test]
fn plain_data_writes_refuse_unsupported_target_metadata_without_mutation() {
    #[derive(Clone, Copy, Debug)]
    enum Shape {
        DataFlags(u16),
        StandardFlags(u32),
        UnsupportedAttribute(u32),
        MultipleNames,
        MultipleLinks,
        DuplicateData,
        TransformedNamedStream,
        DosOnlyName,
    }

    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(512, 64, 0xB0A0_0000_0000_0001);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let seed = FaultInjectingNtfsDevice::new(image);
    let mut seed_engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&seed) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    let (file, _) = seed_engine
        .create_file(&cx, "/", "plain.bin", b"original bytes")
        .into_result()
        .unwrap();
    let clean = seed.snapshot_live();
    let offset = CLUSTER_BYTES + usize::try_from(file.record).unwrap() * RECORD_BYTES;
    let base_attributes = copied_test_record_attributes(&clean[offset..offset + RECORD_BYTES]);

    for shape in [
        Shape::DataFlags(ffs_ondisk::ntfs::COMPRESSED),
        Shape::DataFlags(ffs_ondisk::ntfs::ENCRYPTED),
        Shape::DataFlags(ffs_ondisk::ntfs::SPARSE),
        Shape::DataFlags(0x0002),
        Shape::StandardFlags(0x0200),
        Shape::StandardFlags(0x0400),
        Shape::StandardFlags(0x0800),
        Shape::StandardFlags(0x4000),
        Shape::UnsupportedAttribute(ffs_ondisk::ntfs::ATTRIBUTE_LIST),
        Shape::UnsupportedAttribute(ffs_ondisk::ntfs::REPARSE_POINT),
        Shape::UnsupportedAttribute(0x0100),
        Shape::MultipleNames,
        Shape::MultipleLinks,
        Shape::DuplicateData,
        Shape::TransformedNamedStream,
        Shape::DosOnlyName,
    ] {
        let device = FaultInjectingNtfsDevice::new(clean.clone());
        let mut engine = NtfsTransactionEngine::from_device(
            &cx,
            Arc::clone(&device) as Arc<dyn ByteDevice>,
            0,
            volume_bytes,
            write_options_clean(),
        )
        .unwrap();
        let mut attributes = base_attributes.clone();
        let mut links = 1;
        let attr_kind = |attr: &&mut Vec<u8>| u32::from_le_bytes(attr[0..4].try_into().unwrap());
        match shape {
            Shape::DataFlags(flags) => {
                let data = attributes
                    .iter_mut()
                    .find(|attr| attr_kind(attr) == DATA)
                    .unwrap();
                data[12..14].copy_from_slice(&flags.to_le_bytes());
            }
            Shape::StandardFlags(flags) => {
                let info = attributes
                    .iter_mut()
                    .find(|attr| attr_kind(attr) == 0x10)
                    .unwrap();
                let value = usize::from(u16::from_le_bytes([info[20], info[21]]));
                info[value + 32..value + 36].copy_from_slice(&flags.to_le_bytes());
            }
            Shape::UnsupportedAttribute(kind) => {
                attributes.push(build_resident_attr(kind, 30, &[], false, &[0; 8]));
            }
            Shape::MultipleNames | Shape::DuplicateData => {
                let kind = if matches!(shape, Shape::MultipleNames) {
                    0x30
                } else {
                    DATA
                };
                let mut duplicate = attributes
                    .iter_mut()
                    .find(|attr| attr_kind(attr) == kind)
                    .unwrap()
                    .clone();
                duplicate[14..16].copy_from_slice(&30_u16.to_le_bytes());
                attributes.push(duplicate);
            }
            Shape::MultipleLinks => links = 2,
            Shape::TransformedNamedStream => {
                let mut named =
                    build_resident_attr(DATA, 30, &[u16::from(b'x')], false, b"encrypted ADS");
                named[12..14].copy_from_slice(&ffs_ondisk::ntfs::ENCRYPTED.to_le_bytes());
                attributes.push(named);
            }
            Shape::DosOnlyName => {
                let name = attributes
                    .iter_mut()
                    .find(|attr| attr_kind(attr) == 0x30)
                    .unwrap();
                let value = usize::from(u16::from_le_bytes([name[20], name[21]]));
                name[value + 65] = 2;
            }
        }
        // Change the targeted FILE after clean admission to exercise the
        // per-operation guard, independently of the volume admission checks.
        let changed =
            build_file_record(file.record as u32, file.sequence, links, false, &attributes);
        device
            .write_all_at(&cx, ByteOffset(offset as u64), &changed)
            .unwrap();
        device.sync(&cx).unwrap();
        let before = device.snapshot_live();
        let writes = device.write_bytes_total();
        let events = engine.persistence_trace().len();

        for outcome in [
            engine.write_file_data(&cx, "/plain.bin", b"replacement"),
            engine.write_file_range(&cx, "/plain.bin", 2, b"range"),
            engine.truncate_file(&cx, "/plain.bin", 4),
            engine.write_file_range(&cx, "/plain.bin", u64::MAX, b""),
            engine.truncate_file(&cx, "/plain.bin", b"original bytes".len() as u64),
            engine.unlink_file(&cx, "/plain.bin"),
        ] {
            assert!(
                matches!(
                    outcome,
                    NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
                ),
                "unsupported target {shape:?} must refuse before mutation: {outcome:?}"
            );
            assert_eq!(device.write_bytes_total(), writes, "{shape:?}");
            assert_eq!(device.snapshot_live(), before, "{shape:?}");
            assert_eq!(engine.persistence_trace().len(), events, "{shape:?}");
        }
    }
}

#[test]
fn plain_data_writes_preserve_named_stream_and_security_with_native_case_lookup() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(512, 64, 0xB0A0_0000_0000_0002);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    let (file, _) = engine
        .create_file(&cx, "/", "MixedCase.bin", b"original")
        .into_result()
        .unwrap();
    let before = device.snapshot_live();
    let offset = CLUSTER_BYTES + usize::try_from(file.record).unwrap() * RECORD_BYTES;
    let mut attributes = copied_test_record_attributes(&before[offset..offset + RECORD_BYTES]);
    let security = attributes
        .iter()
        .find(|attr| u32::from_le_bytes(attr[0..4].try_into().unwrap()) == 0x50)
        .unwrap()
        .clone();
    let name: Vec<u16> = "keep".encode_utf16().collect();
    let payload = b"unmodified native named stream";
    attributes.push(build_resident_attr(DATA, 30, &name, false, payload));
    let changed = build_file_record(file.record as u32, file.sequence, 1, false, &attributes);
    device
        .write_all_at(&cx, ByteOffset(offset as u64), &changed)
        .unwrap();
    device.sync(&cx).unwrap();
    engine.check_clean_consistency(&cx).unwrap();

    for replacement in [b"resident replacement".to_vec(), vec![0xB7; 9_000]] {
        let (identity, _) = engine
            .write_file_data(&cx, "/mixedCASE.BIN", &replacement)
            .into_result()
            .unwrap();
        assert_eq!(identity, file);
        engine.check_clean_consistency(&cx).unwrap();
        let volume = engine.volume_view(&cx).unwrap();
        let record = volume
            .record(&cx, file.record, Some(file.sequence))
            .unwrap();
        let named = volume.data_stream(&cx, &record, &name).unwrap();
        assert_eq!(volume.read(&cx, &named, 0, payload.len()).unwrap(), payload);
        let unnamed = volume.data_stream(&cx, &record, &[]).unwrap();
        assert_eq!(
            volume.read(&cx, &unnamed, 0, replacement.len()).unwrap(),
            replacement
        );
        let after = device.snapshot_live();
        let stored = copied_test_record_attributes(&after[offset..offset + RECORD_BYTES]);
        assert!(
            stored.contains(&security),
            "native security descriptor changed"
        );
    }
}

#[test]
fn plain_data_writes_reject_incomplete_nonresident_extent_without_mutation() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(512, 64, 0xB0A0_0000_0000_0003);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    let (file, _) = engine
        .create_file(&cx, "/", "extent.bin", &vec![0x4B; 9_000])
        .into_result()
        .unwrap();
    let pristine = device.snapshot_live();
    let offset = CLUSTER_BYTES + usize::try_from(file.record).unwrap() * RECORD_BYTES;
    let original_attributes =
        copied_test_record_attributes(&pristine[offset..offset + RECORD_BYTES]);
    for compression_unit in [false, true] {
        let mut attributes = original_attributes.clone();
        let data = attributes
            .iter_mut()
            .find(|attr| u32::from_le_bytes(attr[0..4].try_into().unwrap()) == DATA)
            .unwrap();
        if compression_unit {
            data[34..36].copy_from_slice(&4_u16.to_le_bytes());
        } else {
            data[40..48].copy_from_slice(&(4 * CLUSTER_BYTES as u64).to_le_bytes());
        }
        let changed = build_file_record(file.record as u32, file.sequence, 1, false, &attributes);
        device
            .write_all_at(&cx, ByteOffset(offset as u64), &changed)
            .unwrap();
        device.sync(&cx).unwrap();
        let before = device.snapshot_live();
        let writes = device.write_bytes_total();
        let outcome = engine.write_file_data(&cx, "/extent.bin", b"do not discard extents");
        assert!(
            matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(
                    FfsError::Corruption { .. } | FfsError::UnsupportedFeature(_)
                )
            ),
            "incomplete native extent must refuse before allocation or WAL writes: {outcome:?}"
        );
        assert_eq!(device.write_bytes_total(), writes);
        assert_eq!(device.snapshot_live(), before);
    }
}

#[test]
fn unchanged_range_edits_commit_without_reallocation_on_a_full_volume() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(512, 64, 0xB0A0_0000_0000_0004);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    // The fixture reserves 11 clusters, 64 log pages and 32 UpCase clusters.
    // Consume every remaining cluster with a single complete native DATA run.
    let payload = vec![0x5D; (512 - (11 + 64 + 32)) * CLUSTER_BYTES];
    let (file, _) = engine
        .create_file(&cx, "/", "full.bin", &payload)
        .into_result()
        .unwrap();
    engine.check_clean_consistency(&cx).unwrap();
    let baseline = device.snapshot_durable_only();
    let writes = device.write_bytes_total();
    assert!(matches!(
        engine.write_file_data(&cx, "/full.bin", &payload),
        NtfsTxOutcome::NotCommitted(FfsError::NoSpace)
    ));
    assert_eq!(device.write_bytes_total(), writes);

    for truncate in [false, true] {
        let trace_start = engine.persistence_trace().len();
        let outcome = if truncate {
            engine.truncate_file(&cx, "/full.bin", payload.len() as u64)
        } else {
            engine.write_file_range(&cx, "/full.bin", u64::MAX, b"")
        };
        let (identity, token) = outcome.into_result().unwrap();
        assert_eq!(identity, file);
        assert!(token.matches_engine(&engine));
        let events = &engine.persistence_trace()[trace_start..];
        assert!(
            events
                .iter()
                .any(|event| event.stage == NtfsPersistenceStage::LogCommitBarrier)
        );
        assert!(
            events
                .iter()
                .any(|event| event.stage == NtfsPersistenceStage::AckPublished)
        );
        assert!(events.iter().all(|event| !matches!(
            event.stage,
            NtfsPersistenceStage::PayloadDataWrite
                | NtfsPersistenceStage::TargetMetadataWrite
                | NtfsPersistenceStage::MftSlotZeroWrite
        )));
        let after = device.snapshot_durable_only();
        let logfile_start = 10 * CLUSTER_BYTES;
        let logfile_end = (10 + 64) * CLUSTER_BYTES;
        assert_eq!(after[..logfile_start], baseline[..logfile_start]);
        assert_eq!(after[logfile_end..], baseline[logfile_end..]);
        assert_eq!(
            read_all_files_from_clean_volume(&after)["/full.bin"],
            payload
        );
        engine.check_clean_consistency(&cx).unwrap();
    }
    let reopened = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    reopened.check_clean_consistency(&cx).unwrap();
}

#[test]
fn plain_data_writes_require_exact_posix_namespace_spelling() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(512, 64, 0xB0A0_0000_0000_0005);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    let initial = b"POSIX bytes";
    let (file, _) = engine
        .create_file(&cx, "/", "MixedCase.bin", initial)
        .into_result()
        .unwrap();
    let before = device.snapshot_live();
    let file_at = CLUSTER_BYTES + usize::try_from(file.record).unwrap() * RECORD_BYTES;
    let root_at = CLUSTER_BYTES + 5 * RECORD_BYTES;
    let mut file_attrs = copied_test_record_attributes(&before[file_at..file_at + RECORD_BYTES]);
    let file_name = file_attrs
        .iter_mut()
        .find(|attr| u32::from_le_bytes(attr[..4].try_into().unwrap()) == 0x30)
        .unwrap();
    let name_value = usize::from(u16::from_le_bytes(file_name[20..22].try_into().unwrap()));
    file_name[name_value + 65] = 0;

    let mut root_attrs = copied_test_record_attributes(&before[root_at..root_at + RECORD_BYTES]);
    let root_index = root_attrs
        .iter_mut()
        .find(|attr| u32::from_le_bytes(attr[..4].try_into().unwrap()) == 0x90)
        .unwrap();
    let index_value = usize::from(u16::from_le_bytes(root_index[20..22].try_into().unwrap()));
    let entry_offset = u32::from_le_bytes(
        root_index[index_value + 16..index_value + 20]
            .try_into()
            .unwrap(),
    ) as usize;
    root_index[index_value + 16 + entry_offset + 16 + 65] = 0;
    for (offset, record) in [
        (
            file_at,
            build_file_record(file.record as u32, file.sequence, 1, false, &file_attrs),
        ),
        (root_at, build_file_record(5, 5, 1, true, &root_attrs)),
    ] {
        device
            .write_all_at(&cx, ByteOffset(offset as u64), &record)
            .unwrap();
    }
    device.sync(&cx).unwrap();
    engine.check_clean_consistency(&cx).unwrap();
    let before = device.snapshot_live();
    let writes = device.write_bytes_total();
    let trace_len = engine.persistence_trace().len();
    for outcome in [
        engine.write_file_data(&cx, "/mixedcase.bin", b"wrong name"),
        engine.write_file_range(&cx, "/mixedcase.bin", 0, b"wrong name"),
        engine.truncate_file(&cx, "/mixedcase.bin", 0),
        engine.write_file_range(&cx, "/mixedcase.bin", 0, b""),
        engine.truncate_file(&cx, "/mixedcase.bin", initial.len() as u64),
    ] {
        assert!(
            matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(FfsError::Corruption { .. })
            ),
            "case-folded lookup must not select a POSIX native name: {outcome:?}"
        );
        assert_eq!(device.write_bytes_total(), writes);
        assert_eq!(device.snapshot_live(), before);
        assert_eq!(engine.persistence_trace().len(), trace_len);
    }
    engine
        .write_file_range(&cx, "/MixedCase.bin", 1, b"x")
        .into_result()
        .unwrap();
    assert_eq!(
        read_all_files_from_clean_volume(&device.snapshot_durable_only())["/MixedCase.bin"],
        b"PxSIX bytes"
    );
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn oversized_streams_admit_empty_writes_and_bounded_shrink() {
    let cx = Cx::for_testing();
    let image = build_clean_ntfs_image(4352, 64, 0xB0A0_0000_0000_0006);
    let volume_bytes = image.len() as u64 - SECTOR_BYTES as u64;
    let device = FaultInjectingNtfsDevice::new(image);
    let mut engine = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&device) as Arc<dyn ByteDevice>,
        0,
        volume_bytes,
        write_options_clean(),
    )
    .unwrap();
    let limit = ffs_ntfs::transaction::MAX_FILE_EDIT_BYTES;
    let (file, _) = engine
        .create_file(&cx, "/", "large.bin", &vec![0x63; limit as usize + 1])
        .into_result()
        .unwrap();
    engine.check_clean_consistency(&cx).unwrap();
    let volume = engine.volume_view(&cx).unwrap();
    let before = volume
        .record(&cx, file.record, Some(file.sequence))
        .unwrap();
    let trace_start = engine.persistence_trace().len();
    let (identity, token) = engine
        .write_file_range(&cx, "/large.bin", u64::MAX, b"")
        .into_result()
        .unwrap();
    assert_eq!(identity, file);
    assert!(token.matches_engine(&engine));
    assert!(
        engine.persistence_trace()[trace_start..]
            .iter()
            .all(|event| event.stage != NtfsPersistenceStage::PayloadDataWrite)
    );
    let volume = engine.volume_view(&cx).unwrap();
    let after = volume
        .record(&cx, file.record, Some(file.sequence))
        .unwrap();
    assert_eq!(after.used_bytes(), before.used_bytes());
    let stream = volume.data_stream(&cx, &after, &[]).unwrap();
    assert_eq!(stream.size, limit + 1);
    assert_eq!(volume.read(&cx, &stream, limit, 1).unwrap(), vec![0x63]);

    let writes = device.write_bytes_total();
    for outcome in [
        engine.write_file_range(&cx, "/large.bin", 0, b"x"),
        engine.truncate_file(&cx, "/large.bin", limit + 1),
    ] {
        let NtfsTxOutcome::NotCommitted(error) = outcome else {
            panic!("oversized edit requests must fail before publication");
        };
        assert_eq!(error.to_errno(), libc::EFBIG);
        assert_eq!(device.write_bytes_total(), writes);
    }

    // The reader rejects requests larger than 16 MiB. Successful shrink proves
    // the old suffix is discarded without trying to materialize the whole file.
    engine
        .truncate_file(&cx, "/large.bin", 16)
        .into_result()
        .unwrap();
    let volume = engine.volume_view(&cx).unwrap();
    let record = volume
        .record(&cx, file.record, Some(file.sequence))
        .unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    assert_eq!(stream.size, 16);
    assert_eq!(volume.read(&cx, &stream, 0, 16).unwrap(), vec![0x63; 16]);
    engine.check_clean_consistency(&cx).unwrap();
}
