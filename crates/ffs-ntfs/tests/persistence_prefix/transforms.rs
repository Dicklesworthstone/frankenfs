//! Comprehensive integration, negative-control, and persistence-prefix fault-cut
//! tests for native NTFS transforms (sparse/hole-punch, LZNT1 compression, WOF
//! decompression-on-write), `$Secure` multi-stripe/inheritance/DACL/SACL + NTFS 3.0
//! `0x50` security, reparse points & `$Extend/$Reparse::$R`, `$OBJECT_ID` &
//! `$Extend/$ObjId::$O`, active `$Extend/$UsnJrnl`, `$EA`, and explicit key-scoped
//! EFS encryption/decryption (`bd-h8n46`).

use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_core::vfs::XattrSetMode;
use ffs_core::{FileType, FsOps, RequestScope, SeekWhence, SetAttrRequest};
use ffs_error::FfsError;
use ffs_ntfs::NtfsVolume;
use ffs_ntfs::efs::{NtfsEfsKey, StaticEfsKeyScope};
use ffs_ntfs::formatter::{NtfsFormatOptions, NtfsFormatVersion, format_image_file};
use ffs_ntfs::reader::check::{NtfsCheckLimits, check_volume_device};
use ffs_ntfs::reader::filesystem::NtfsFs;
use ffs_ntfs::reader::security::SecurityCheckLimits;
use ffs_ntfs::security_policy::{NtfsSecurityPatch, NtfsSidMap, NtfsSidPolicy, build_simple_ace};
use ffs_ntfs::transaction::{
    DEFAULT_NTFS_FILETIME, NtfsObjectIdData, NtfsPersistenceStage, NtfsTransactionEngine,
    NtfsTxOutcome,
};
use ffs_ondisk::ntfs::efs::EFS_STREAM_NAME;
use ffs_ondisk::ntfs::reparse::{MOUNT_POINT_TAG, NtfsReparseData, NtfsReparsePoint};
use ffs_ondisk::ntfs::{DATA, NtfsReference, REPARSE_POINT, SPARSE};
use ffs_ondisk::ntfs_security::{
    ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_INHERIT_ONLY, ACE_FLAG_INHERITED, ACE_FLAG_OBJECT_INHERIT,
    ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_DENIED, ACE_TYPE_SYSTEM_AUDIT, FILE_ALL_ACCESS,
    FILE_READ_DATA, FILE_WRITE_DATA, NtfsAccessToken, NtfsAcl, NtfsSecurityDescriptor, NtfsSid,
    SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE,
};
use ffs_types::InodeNumber;

use super::{FaultInjectingNtfsDevice, SECTOR_BYTES, write_options_clean, write_options_recover};

fn format_to_fault_device(
    cx: &Cx,
    size_mib: u64,
    cluster_bytes: u32,
    version: NtfsFormatVersion,
    serial: u64,
) -> (Arc<FaultInjectingNtfsDevice>, u64) {
    let dir = tempfile::tempdir().unwrap();
    let img_path = dir.path().join("ntfs.img");
    let mut opts = NtfsFormatOptions::new_image(img_path.clone(), size_mib);
    opts.cluster_bytes = Some(cluster_bytes);
    opts.version = version;
    opts.serial = Some(serial);
    opts.logfile_bytes = Some(256 * 1024);
    let rep = format_image_file(cx, &opts).unwrap();
    assert!(rep.boot_published && rep.check_clean);
    let raw = std::fs::read(&img_path).unwrap();
    let vol_bytes = raw.len() as u64 - SECTOR_BYTES as u64;
    let dev = FaultInjectingNtfsDevice::new(raw);
    (dev, vol_bytes)
}

fn open_clean_engine(
    cx: &Cx,
    dev: &Arc<FaultInjectingNtfsDevice>,
    vol_bytes: u64,
) -> NtfsTransactionEngine {
    NtfsTransactionEngine::from_device(
        cx,
        Arc::clone(dev) as Arc<dyn ByteDevice>,
        0,
        vol_bytes,
        write_options_clean(),
    )
    .unwrap()
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn read_file_by_path(cx: &Cx, engine: &NtfsTransactionEngine, path: &str) -> Vec<u8> {
    let vol = engine.volume_view(cx).unwrap();
    let rec = vol.resolve(cx, path).unwrap();
    let stream = vol.data_stream(cx, &rec, &[]).unwrap();
    vol.read(cx, &stream, 0, usize::try_from(stream.size).unwrap())
        .unwrap()
}

#[test]
fn ntfs_sparse_toggle_large_tail_and_hole_punch_fiemap_seek_roundtrip() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xBD84_0001_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();

    // 1. Create file, mark SPARSE, extend logical tail to 24 MiB (> 16 MiB staging cap!).
    let file_ref = engine
        .create_file_at(&cx, root, &utf16("sparse.bin"), b"head-prefix")
        .into_result()
        .unwrap();
    engine
        .set_sparse_at(&cx, file_ref, &[], true, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    let large_len = 24 * 1024 * 1024_u64;
    engine
        .truncate_stream_at(&cx, file_ref, &[], large_len, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();

    // Write 12 KiB (3 clusters) at offset 20 MiB without allocating the 20 MiB hole.
    let write_off = 20 * 1024 * 1024_u64;
    let payload = vec![0x5Au8; 12 * 1024];
    engine
        .write_stream_range(&cx, file_ref, &[], write_off, &payload)
        .into_result()
        .unwrap();

    // Verify sparse savings: allocated << 24 MiB.
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/sparse.bin").unwrap();
        let st = vol.data_stream(&cx, &rec, &[]).unwrap();
        assert_eq!(st.size, large_len);
        assert_eq!(st.allocated, 4 * 4096); // 1 head cluster + 3 clusters at 20 MiB
        assert_eq!(vol.read(&cx, &st, 0, 11).unwrap(), b"head-prefix");
        assert_eq!(vol.read(&cx, &st, 8192, 4096).unwrap(), vec![0_u8; 4096]);
        assert_eq!(
            vol.read(&cx, &st, write_off, payload.len()).unwrap(),
            payload
        );
    }

    // 2. Punch middle 4 KiB cluster of the 12 KiB run -> reclaims 1 cluster!
    let reclaimed = engine
        .punch_hole_at(
            &cx,
            file_ref,
            &[],
            write_off + 4096,
            4096,
            false,
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    assert_eq!(reclaimed, 1);

    // Verify hole zeros + intact surrounding clusters + FIEMAP/SEEK_HOLE/SEEK_DATA via NtfsFs.
    let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let attr = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("sparse.bin"))
        .unwrap();
    assert_eq!(attr.size, large_len);
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, write_off, 4096).unwrap(),
        vec![0x5Au8; 4096]
    );
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, write_off + 4096, 4096)
            .unwrap(),
        vec![0_u8; 4096]
    );
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, write_off + 8192, 4096)
            .unwrap(),
        vec![0x5Au8; 4096]
    );
    let extents = fs.fiemap(&cx, &mut scope, attr.ino, 0, u64::MAX).unwrap();
    assert_eq!(extents.len(), 3);
    assert_eq!(extents[0].logical, 0);
    assert_eq!(extents[1].logical, write_off);
    assert_eq!(extents[2].logical, write_off + 8192);
    assert_eq!(
        fs.lseek(&cx, &mut scope, attr.ino, 4096, SeekWhence::Data)
            .unwrap(),
        write_off
    );
    assert_eq!(
        fs.lseek(&cx, &mut scope, attr.ino, write_off, SeekWhence::Hole)
            .unwrap(),
        write_off + 4096
    );

    // 3. Punch via FsOps::fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)!
    fs.fallocate(
        &cx,
        &mut scope,
        attr.ino,
        write_off + 8192,
        4096,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
    )
    .unwrap();
    assert_eq!(
        fs.read(&cx, &mut scope, attr.ino, write_off + 8192, 4096)
            .unwrap(),
        vec![0_u8; 4096]
    );
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);

    // 4. Disable sparse on a smaller file -> holes materialize to real allocated clusters.
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    let mat_ref = engine
        .create_file_at(&cx, root, &utf16("materialize.bin"), &[])
        .into_result()
        .unwrap();
    engine
        .set_sparse_at(&cx, mat_ref, &[], true, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    engine
        .write_stream_range(&cx, mat_ref, &[], 16384, b"tail!")
        .into_result()
        .unwrap();
    engine
        .set_sparse_at(&cx, mat_ref, &[], false, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    let readback = read_file_by_path(&cx, &engine, "/materialize.bin");
    assert_eq!(readback.len(), 16389);
    assert!(readback[..16384].iter().all(|&b| b == 0));
    assert_eq!(&readback[16384..], b"tail!");
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn ntfs_lznt1_compression_partial_write_truncate_dir_inherit_and_incompressible() {
    let cx = Cx::for_testing();
    for cluster_bytes in [4096_u32, 512_u32] {
        let (dev, vol_bytes) = format_to_fault_device(
            &cx,
            16,
            cluster_bytes,
            NtfsFormatVersion::V3_1,
            0xBD84_0002_0000_0000 | u64::from(cluster_bytes),
        );
        let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
        let root = engine.resolve_path_reference(&cx, "/").unwrap();

        // 1. Compressible 128 KiB payload -> enable LZNT1 compression -> verify real space savings!
        let mut expected = Vec::with_capacity(128 * 1024);
        for i in 0..4096_u32 {
            expected.extend_from_slice(b"FRANKENFS-LZNT1-COMPRESS-PATTERN");
            let _ = i;
        }
        let file_ref = engine
            .create_file_at(&cx, root, &utf16("comp.bin"), &expected)
            .into_result()
            .unwrap();
        engine
            .set_compression_at(&cx, file_ref, true, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        {
            let vol = engine.volume_view(&cx).unwrap();
            let rec = vol.resolve(&cx, "/comp.bin").unwrap();
            let st = vol.data_stream(&cx, &rec, &[]).unwrap();
            assert_eq!(st.size, expected.len() as u64);
            assert!(
                st.allocated < st.size / 4,
                "expected LZNT1 compression savings for cluster={cluster_bytes}: alloc={} size={}",
                st.allocated,
                st.size
            );
        }
        assert_eq!(read_file_by_path(&cx, &engine, "/comp.bin"), expected);

        // 2. Unaligned cross-unit partial overwrite with incompressible pseudo-random bytes!
        let mut incomp = vec![0_u8; (cluster_bytes as usize) * 16];
        let mut lcg = 0x1234_5678_9ABC_DEF0_u64;
        for b in &mut incomp {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (lcg >> 33) as u8;
        }
        let patch_off = (cluster_bytes as usize) * 8 + 137;
        let patch_len = incomp.len().min(expected.len() - patch_off);
        engine
            .write_stream_range(&cx, file_ref, &[], patch_off as u64, &incomp[..patch_len])
            .into_result()
            .unwrap();
        expected[patch_off..patch_off + patch_len].copy_from_slice(&incomp[..patch_len]);
        assert_eq!(read_file_by_path(&cx, &engine, "/comp.bin"), expected);

        // 3. Extend + write an all-zero unit + shrink!
        let unit_bytes = u64::from(cluster_bytes) * 16;
        let extended_len = expected.len() as u64 + unit_bytes + 777;
        engine
            .truncate_stream_at(&cx, file_ref, &[], extended_len, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        expected.resize(extended_len as usize, 0);
        assert_eq!(read_file_by_path(&cx, &engine, "/comp.bin"), expected);

        let shrunk_len = (unit_bytes + 513).min(expected.len() as u64);
        engine
            .truncate_stream_at(&cx, file_ref, &[], shrunk_len, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        expected.truncate(shrunk_len as usize);
        assert_eq!(read_file_by_path(&cx, &engine, "/comp.bin"), expected);

        // 4. Toggle compression OFF -> decompress cleanly!
        engine
            .set_compression_at(&cx, file_ref, false, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        assert_eq!(read_file_by_path(&cx, &engine, "/comp.bin"), expected);

        // 5. Directory compression inheritance: new child created inside compressed dir inherits compression!
        let dir_ref = engine
            .mkdir_at(&cx, root, &utf16("cdir"))
            .into_result()
            .unwrap();
        engine
            .set_compression_at(&cx, dir_ref, true, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
        let child_data = vec![b'A'; (cluster_bytes as usize) * 32];
        let _child_ref = engine
            .create_file_at(&cx, dir_ref, &utf16("inherited.bin"), &child_data)
            .into_result()
            .unwrap();
        {
            let vol = engine.volume_view(&cx).unwrap();
            let rec = vol.resolve(&cx, "/cdir/inherited.bin").unwrap();
            let st = vol.data_stream(&cx, &rec, &[]).unwrap();
            assert_eq!(st.size, child_data.len() as u64);
            assert!(
                st.allocated < st.size / 4,
                "child did not inherit LZNT1 compression from parent dir"
            );
            assert_eq!(
                read_file_by_path(&cx, &engine, "/cdir/inherited.bin"),
                child_data
            );
        }
        engine.check_clean_consistency(&cx).unwrap();
    }
}

#[test]
fn ntfs_wof_decompression_on_write_materializes_plaintext_and_cleans_reparse() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xBD84_0003_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();

    // Build an authentic single-chunk WOF XPRESS4K file (uncompressed single chunk stored
    // verbatim in `WofCompressedData`, sparse 2048-byte placeholder unnamed `$DATA`, and
    // WOF reparse tag `0x8000_0017` installed on the base record).
    let wof_initial = b"WOF-INITIAL-PLAINTEXT-PAYLOAD-0123456789".repeat(50); // 2000 bytes (< 4096)
    let wof_ref = engine
        .create_file_at(&cx, root, &utf16("wof.bin"), &[])
        .into_result()
        .unwrap();
    engine
        .set_sparse_at(&cx, wof_ref, &[], true, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    engine
        .truncate_stream_at(
            &cx,
            wof_ref,
            &[],
            wof_initial.len() as u64,
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    engine
        .create_stream(&cx, wof_ref, &utf16("WofCompressedData"), &wof_initial)
        .into_result()
        .unwrap();

    // Install authentic WOF reparse point (version=1, provider=2, file_ver=1, alg=0 XPRESS4K)
    // by writing a temporary opaque tag first? No — `set_reparse_point_at` intentionally refuses
    // direct WOF installation; patch `$REPARSE_POINT` cleanly on-disk via a small helper?
    // Even cleaner: verify `validate_writable_reparse_point` refuses manual WOF installation,
    // AND patch the test fixture's record with a real WOF reparse point so `NtfsVolume::data_stream`
    // opens it via `Storage::Wof`!
    let mut wof_body = Vec::with_capacity(16);
    wof_body.extend_from_slice(&1_u32.to_le_bytes());
    wof_body.extend_from_slice(&2_u32.to_le_bytes());
    wof_body.extend_from_slice(&1_u32.to_le_bytes());
    wof_body.extend_from_slice(&0_u32.to_le_bytes());
    let wof_point = NtfsReparsePoint {
        tag: 0x8000_0017,
        guid: None,
        data: NtfsReparseData::Opaque(wof_body),
    };
    assert!(matches!(
        engine.set_reparse_point_at(&cx, wof_ref, &wof_point, true, DEFAULT_NTFS_FILETIME),
        NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
    ));
    // Install a valid opaque placeholder reparse point of exact same 24-byte encoded length
    // (`tag=0x9000_0017`, 16-byte identical payload) so `$REPARSE_POINT` attribute & `$Reparse::$R`
    // exist in the MFT record, then flip the 4-byte tag word in the raw image to `0x8000_0017`
    // and recalculate USA fixups — producing a 100% genuine WOF-backed MFT record!
    let placeholder_point = NtfsReparsePoint {
        tag: 0x9000_0017,
        guid: None,
        data: wof_point.data.clone(),
    };
    engine
        .set_reparse_point_at(
            &cx,
            wof_ref,
            &placeholder_point,
            true,
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    drop(engine);

    // Patch tag `0x9000_0017` -> `0x8000_0017` in the MFT record (updating USA fixups & `$Reparse::$R` isn't needed for reader).
    let mut img = dev.snapshot_durable_only();
    let rec_no = wof_ref.record as usize;
    let vol_probe = NtfsVolume::from_device(
        &cx,
        Box::new(FaultInjectingNtfsDevice::new(img.clone())),
        0,
        vol_bytes,
    )
    .unwrap();
    let mft_rec_off = (vol_probe.geometry.mft_cluster()
        * u64::from(vol_probe.geometry.cluster_bytes())) as usize
        + rec_no * (vol_probe.geometry.record_bytes() as usize);
    let rec_len = vol_probe.geometry.record_bytes() as usize;
    let mut restored =
        ffs_ondisk::ntfs::restore_record(&img[mft_rec_off..mft_rec_off + rec_len], b"FILE")
            .unwrap();
    let old_tag = 0x9000_0017_u32.to_le_bytes();
    let new_tag = 0x8000_0017_u32.to_le_bytes();
    let mut replaced_count = 0;
    for pos in 0..restored.len().saturating_sub(4) {
        if restored[pos..pos + 4] == old_tag {
            restored[pos..pos + 4].copy_from_slice(&new_tag);
            replaced_count += 1;
        }
    }
    assert!(replaced_count >= 1);
    let usa_off = u16::from_le_bytes([restored[4], restored[5]]) as usize;
    let usa_cnt = u16::from_le_bytes([restored[6], restored[7]]) as usize;
    let token = [0x22_u8, 0x00];
    restored[usa_off..usa_off + 2].copy_from_slice(&token);
    for s in 1..usa_cnt {
        let end = s * 512;
        let orig = [restored[end - 2], restored[end - 1]];
        restored[usa_off + s * 2..usa_off + s * 2 + 2].copy_from_slice(&orig);
        restored[end - 2..end].copy_from_slice(&token);
    }
    img[mft_rec_off..mft_rec_off + rec_len].copy_from_slice(&restored);
    let wof_dev = FaultInjectingNtfsDevice::new(img);

    // Confirm reader opens it as genuine WOF and reads exact initial plaintext!
    let mut engine = open_clean_engine(&cx, &wof_dev, vol_bytes);
    assert_eq!(read_file_by_path(&cx, &engine, "/wof.bin"), wof_initial);

    // Perform positioned write -> triggers WOF decompression-on-write!
    engine
        .write_stream_range(&cx, wof_ref, &[], 4, b"DECOMPRESSED!")
        .into_result()
        .unwrap();
    let mut expected = wof_initial;
    expected[4..17].copy_from_slice(b"DECOMPRESSED!");
    assert_eq!(read_file_by_path(&cx, &engine, "/wof.bin"), expected);

    // Verify `WofCompressedData` AND `$REPARSE_POINT` are completely gone!
    let vol = engine.volume_view(&cx).unwrap();
    let rec = vol.resolve(&cx, "/wof.bin").unwrap();
    assert!(vol.reparse_point(&cx, &rec).unwrap().is_none());
    let streams = vol.data_streams(&cx, &rec).unwrap();
    assert_eq!(streams.len(), 1);
    assert!(streams[0].name.is_empty());
    engine.check_clean_consistency(&cx).unwrap();
}

#[test]
fn ntfs_secure_intern_dedup_multistripe_256k_inheritance_hardlink_dacl_sacl_and_ntfs30() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        24,
        4096,
        NtfsFormatVersion::V3_1,
        0xBD84_0004_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();

    let alice_sid = NtfsSid {
        authority: 5,
        subauthorities: vec![88, 1, 1001],
    };
    let bob_sid = NtfsSid {
        authority: 5,
        subauthorities: vec![88, 1, 1002],
    };
    let grp_sid = NtfsSid {
        authority: 5,
        subauthorities: vec![88, 2, 2000],
    };
    let creator_owner = NtfsSid::creator_owner();

    // 1. Build a descriptor with SACL + DENY-before-ALLOW DACL + inheritable OI/CI/IO ACEs.
    let sd_parent = NtfsSecurityDescriptor {
        revision: 1,
        resource_manager_control: 0,
        control: SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT,
        owner: Some(alice_sid.clone()),
        group: Some(grp_sid.clone()),
        sacl: NtfsAcl {
            present: true,
            offset: 0,
            revision: Some(2),
            ace_count: Some(1),
            size: None,
            aces: vec![build_simple_ace(
                ACE_TYPE_SYSTEM_AUDIT,
                0xC0,
                FILE_WRITE_DATA,
                NtfsSid::world_everyone(),
            )],
            padding: Vec::new(),
        },
        dacl: NtfsAcl {
            present: true,
            offset: 0,
            revision: Some(2),
            ace_count: Some(3),
            size: None,
            aces: vec![
                // Explicit DENY write for Bob (inheritable to files & subdirs)
                build_simple_ace(
                    ACE_TYPE_ACCESS_DENIED,
                    ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT,
                    FILE_WRITE_DATA,
                    bob_sid.clone(),
                ),
                // Inherit-only CREATOR_OWNER full access -> replaced with owner on child!
                build_simple_ace(
                    ACE_TYPE_ACCESS_ALLOWED,
                    ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_INHERIT_ONLY,
                    FILE_ALL_ACCESS,
                    creator_owner,
                ),
                // Broad ALLOW Everyone read+write (Bob's earlier DENY MUST beat this!)
                build_simple_ace(
                    ACE_TYPE_ACCESS_ALLOWED,
                    ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT,
                    FILE_READ_DATA | FILE_WRITE_DATA,
                    NtfsSid::world_everyone(),
                ),
            ],
            padding: Vec::new(),
        },
    };
    let parent_sd_bytes = sd_parent.encode().unwrap();

    let dir_a = engine
        .mkdir_at(&cx, root, &utf16("sec_a"))
        .into_result()
        .unwrap();
    let dir_b = engine
        .mkdir_at(&cx, root, &utf16("sec_b"))
        .into_result()
        .unwrap();
    let id_a = engine
        .set_security_at(&cx, dir_a, &parent_sd_bytes, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap()
        .expect("NTFS 3.1 must assign $Secure security_id");
    let id_b = engine
        .set_security_at(&cx, dir_b, &parent_sd_bytes, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap()
        .expect("NTFS 3.1 must assign $Secure security_id");
    // Exact `$SDH` hash + byte deduplication!
    assert_eq!(id_a, id_b);

    // 2. Create child inside `sec_a` -> verify inheritance + DENY-before-ALLOW!
    let child_ref = engine
        .create_file_at(&cx, dir_a, &utf16("secret.txt"), b"classified")
        .into_result()
        .unwrap();
    let bob_tok = NtfsAccessToken {
        user: bob_sid.clone(),
        groups: vec![grp_sid.clone()],
    };
    let alice_tok = NtfsAccessToken {
        user: alice_sid.clone(),
        groups: vec![grp_sid.clone()],
    };
    assert!(
        engine
            .check_access(&cx, child_ref, &alice_tok, FILE_WRITE_DATA)
            .unwrap()
    );
    assert!(
        engine
            .check_access(&cx, child_ref, &bob_tok, FILE_READ_DATA)
            .unwrap()
    );
    assert!(
        !engine
            .check_access(&cx, child_ref, &bob_tok, FILE_WRITE_DATA)
            .unwrap(),
        "explicit DENY ACE must beat subsequent ALLOW Everyone ACE"
    );
    {
        let vol = engine.volume_view(&cx).unwrap();
        let child_rec = vol.resolve(&cx, "/sec_a/secret.txt").unwrap();
        let info = vol.security_descriptor(&cx, &child_rec).unwrap();
        assert!(
            info.descriptor
                .dacl
                .aces
                .iter()
                .any(|a| (a.flags & ACE_FLAG_INHERITED) != 0)
        );
        assert!(info.descriptor.sacl.present && info.descriptor.sacl.aces.len() == 1);
    }

    // 3. Hard-link `secret.txt` into `sec_b/alias.txt`: security update applies to both links!
    engine
        .link_at(&cx, child_ref, dir_b, &utf16("alias.txt"))
        .into_result()
        .unwrap();
    let patch_owner = NtfsSecurityPatch {
        owner: Some(bob_sid.clone()),
        ..NtfsSecurityPatch::default()
    };
    engine
        .patch_security_at(&cx, child_ref, &patch_owner, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec_a = vol.resolve(&cx, "/sec_a/secret.txt").unwrap();
        let rec_b = vol.resolve(&cx, "/sec_b/alias.txt").unwrap();
        let info_a = vol.security_descriptor(&cx, &rec_a).unwrap();
        let info_b = vol.security_descriptor(&cx, &rec_b).unwrap();
        assert_eq!(info_a.security_id, info_b.security_id);
        assert_eq!(info_a.descriptor.owner.as_ref(), Some(&bob_sid));
        // SACL preserved across patch!
        assert_eq!(info_a.descriptor.sacl.aces.len(), 1);
    }

    // 4. Push `$Secure::$SDS` across the 256 KiB even/odd stripe mirror boundary AND
    //    split `$SII`/`$SDH` into external `INDX` blocks!
    let target_ref = engine
        .create_file_at(&cx, root, &utf16("stripe_driver.bin"), b"x")
        .into_result()
        .unwrap();
    // Each descriptor has 60 distinct ACEs (~2.2 KiB); 130 distinct descriptors => > 280 KiB > 256 KiB!
    for round in 0_u32..130 {
        let mut aces = Vec::with_capacity(60);
        for k in 0_u32..60 {
            aces.push(build_simple_ace(
                ACE_TYPE_ACCESS_ALLOWED,
                0,
                FILE_READ_DATA,
                NtfsSid {
                    authority: 5,
                    subauthorities: vec![21, 9000 + round, 100 + k, 1000 + round * 64 + k],
                },
            ));
        }
        let big_sd = NtfsSecurityDescriptor {
            revision: 1,
            resource_manager_control: 0,
            control: SE_SELF_RELATIVE | SE_DACL_PRESENT,
            owner: Some(alice_sid.clone()),
            group: Some(grp_sid.clone()),
            sacl: NtfsAcl {
                present: false,
                offset: 0,
                revision: None,
                ace_count: None,
                size: None,
                aces: Vec::new(),
                padding: Vec::new(),
            },
            dacl: NtfsAcl {
                present: true,
                offset: 0,
                revision: Some(2),
                ace_count: Some(aces.len() as u16),
                size: None,
                aces,
                padding: Vec::new(),
            },
        };
        let raw = big_sd.encode().unwrap();
        engine
            .set_security_at(&cx, target_ref, &raw, DEFAULT_NTFS_FILETIME)
            .into_result()
            .unwrap();
    }
    {
        let vol = engine.volume_view(&cx).unwrap();
        let sec_rep = vol
            .check_security_references(&cx, SecurityCheckLimits::default(), 1_048_576)
            .unwrap();
        assert!(
            sec_rep.is_consistent(),
            "multi-stripe $Secure check failed: {:?}",
            sec_rep.issues
        );
        assert!(sec_rep.store.security_ids >= 130);
        assert!(
            sec_rep.store.index_blocks >= 2,
            "expected external $SII/$SDH INDX split"
        );
        assert!(
            sec_rep.store.descriptor_bytes > 262_144,
            "expected >256 KiB $SDS multi-stripe"
        );
    }

    // 5. Mapped-SID `NtfsFs`: chmod/chown preserve SACL & enforce DACL PermissionDenied!
    let mapped_policy = NtfsSidPolicy::Mapped {
        caller_uid: 1001,
        caller_gid: 2000,
        map: NtfsSidMap {
            enforce_acl: true,
            posix_nfs_sids: true,
            fallback_uid: 0,
            fallback_gid: 0,
            ..NtfsSidMap::default()
        },
    };
    let fs = NtfsFs::from_engine_with_policy(&cx, engine, mapped_policy).unwrap();
    let mut scope = RequestScope::empty();
    let dir_attr = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("sec_a"))
        .unwrap();
    assert_eq!(dir_attr.uid, 1001);
    assert_eq!(dir_attr.gid, 2000);
    let sec_file = fs
        .lookup(&cx, &mut scope, dir_attr.ino, OsStr::new("secret.txt"))
        .unwrap();
    assert_eq!(sec_file.uid, 1002); // Bob owns it after step 3
    let updated = fs
        .setattr(
            &cx,
            &mut scope,
            sec_file.ino,
            &SetAttrRequest {
                mode: Some(0o640),
                uid: Some(1001),
                ..SetAttrRequest::default()
            },
        )
        .unwrap();
    assert_eq!(updated.uid, 1001);
    assert_eq!(updated.perm & 0o777, 0o640);
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);

    // Reopen as Bob (uid=1002, not in group 2000, mode=0o640 -> other=0 -> DENIED read!).
    let eng2 = open_clean_engine(&cx, &dev, vol_bytes);
    let bob_policy = NtfsSidPolicy::Mapped {
        caller_uid: 1002,
        caller_gid: 2099,
        map: NtfsSidMap {
            enforce_acl: true,
            posix_nfs_sids: true,
            ..NtfsSidMap::default()
        },
    };
    let fs_bob = NtfsFs::from_engine_with_policy(&cx, eng2, bob_policy).unwrap();
    let dir_a_bob = fs_bob
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("sec_a"))
        .unwrap();
    let secret_bob = fs_bob
        .lookup(&cx, &mut scope, dir_a_bob.ino, OsStr::new("secret.txt"))
        .unwrap();
    assert!(matches!(
        fs_bob.read(&cx, &mut scope, secret_bob.ino, 0, 10),
        Err(FfsError::PermissionDenied)
    ));
    drop(fs_bob);

    // 6. Native NTFS 3.0 volume transaction + 0x50 `$SECURITY_DESCRIPTOR` round-trip!
    let (dev30, vol30_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_0,
        0xBD84_0030_0000_0001,
    );
    let mut eng30 = open_clean_engine(&cx, &dev30, vol30_bytes);
    assert_eq!(eng30.version(), [3, 0]);
    let root30 = eng30.resolve_path_reference(&cx, "/").unwrap();
    let f30 = eng30
        .create_file_at(&cx, root30, &utf16("ntfs30.txt"), b"hello-win2k")
        .into_result()
        .unwrap();
    let assigned30 = eng30
        .set_security_at(&cx, f30, &parent_sd_bytes, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    assert!(
        assigned30.is_none(),
        "NTFS 3.0 stores 0x50 $SECURITY_DESCRIPTOR, not $Secure ID"
    );
    assert_eq!(
        read_file_by_path(&cx, &eng30, "/ntfs30.txt"),
        b"hello-win2k"
    );
    let chk30 = check_volume_device(
        &cx,
        Arc::clone(&dev30) as Arc<dyn ByteDevice>,
        0,
        vol30_bytes,
        NtfsCheckLimits::default(),
    )
    .unwrap();
    assert!(
        chk30.is_clean(),
        "NTFS 3.0 check failed: {:?}",
        chk30.issues
    );
}

#[test]
fn ntfs_reparse_symlink_junction_opaque_objid_usnjrnl_ea_and_refusals() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xBD84_0005_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();

    // 1. Enable active `$Extend/$UsnJrnl` with small 8 KiB max so we also prove sparse head trimming!
    let _usn_ref = engine
        .enable_usn_journal(&cx, 8192, 4096, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();

    // 2. Symlink + mount-point junction + opaque reparse preservation & refusal!
    let _sym_ref = engine
        .create_symlink_at(
            &cx,
            root,
            &utf16("rel_link"),
            &utf16("sub\\target.txt"),
            true,
            false,
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    let junc_dir = engine
        .mkdir_at(&cx, root, &utf16("junction_dir"))
        .into_result()
        .unwrap();
    let mount_point = NtfsReparsePoint {
        tag: MOUNT_POINT_TAG,
        guid: None,
        data: NtfsReparseData::MountPoint {
            substitute: utf16("\\??\\C:\\mounted"),
            print: utf16("C:\\mounted"),
        },
    };
    engine
        .set_reparse_point_at(&cx, junc_dir, &mount_point, false, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();

    // Opaque third-party tag (0x9000_101A): refused without allow_opaque, admitted with allow_opaque.
    let opaque_file = engine
        .create_file_at(&cx, root, &utf16("cloud_placeholder.bin"), b"backing")
        .into_result()
        .unwrap();
    let opaque_rp = NtfsReparsePoint {
        tag: 0x9000_101A,
        guid: None,
        data: NtfsReparseData::Opaque(vec![0xFE, 0xCA, 0x01, 0x02, 0x03, 0x04]),
    };
    assert!(matches!(
        engine.set_reparse_point_at(&cx, opaque_file, &opaque_rp, false, DEFAULT_NTFS_FILETIME),
        NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
    ));
    engine
        .set_reparse_point_at(&cx, opaque_file, &opaque_rp, true, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    // Ordinary $DATA read & write MUST fail closed while metadata/rename preserve opaque payload!
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/cloud_placeholder.bin").unwrap();
        assert!(matches!(
            vol.data_stream(&cx, &rec, &[]),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }
    assert!(matches!(
        engine.write_stream_range(&cx, opaque_file, &[], 0, b"nope"),
        NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
    ));
    engine
        .rename_at(
            &cx,
            root,
            &utf16("cloud_placeholder.bin"),
            root,
            &utf16("cloud_moved.bin"),
            opaque_file,
            true,
        )
        .into_result()
        .unwrap();
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/cloud_moved.bin").unwrap();
        let rp = vol.reparse_point(&cx, &rec).unwrap().unwrap();
        assert_eq!(rp, opaque_rp);
    }

    // 3. `$OBJECT_ID` (`0x40`) + `$Extend/$ObjId::$O` uniqueness & cleanup!
    let f1 = engine
        .create_file_at(&cx, root, &utf16("obj1.bin"), b"one")
        .into_result()
        .unwrap();
    let f2 = engine
        .create_file_at(&cx, root, &utf16("obj2.bin"), b"two")
        .into_result()
        .unwrap();
    let oid = NtfsObjectIdData {
        object_id: [0x11; 16],
        birth_volume_id: [0x22; 16],
        birth_object_id: [0x33; 16],
        domain_id: [0x00; 16],
    };
    engine
        .set_object_id_at(&cx, f1, oid, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    // Duplicate GUID on a different file MUST fail with Exists!
    assert!(matches!(
        engine.set_object_id_at(&cx, f2, oid, DEFAULT_NTFS_FILETIME),
        NtfsTxOutcome::NotCommitted(FfsError::Exists)
    ));
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/obj1.bin").unwrap();
        assert_eq!(vol.object_id(&cx, &rec).unwrap(), Some(oid));
    }
    engine
        .remove_object_id_at(&cx, f1, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    // Once removed from f1, f2 may claim the same GUID cleanly!
    engine
        .set_object_id_at(&cx, f2, oid, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    engine
        .unlink_at(&cx, root, &utf16("obj2.bin"), f2)
        .into_result()
        .unwrap();

    // 4. Drive > 160 USN records (exceeding 8 KiB + 4 KiB delta => triggers 4 KiB page pad + head trim!).
    for i in 0_u32..165 {
        let payload = format!("usn-update-{i:04}");
        engine
            .write_stream_range(&cx, f1, &[], 0, payload.as_bytes())
            .into_result()
            .unwrap();
    }
    {
        let vol = engine.volume_view(&cx).unwrap();
        let summary = vol.usn_summary(&cx).unwrap().expect("active $UsnJrnl");
        assert!(
            summary.next_usn > 12_288,
            "expected USN journal growth past 12 KiB"
        );
        assert!(
            summary.lowest_valid_usn >= 4096,
            "expected sparse head trimming to advance lowest_valid_usn: {summary:?}"
        );
        assert!(summary.records_inspected >= 10);
    }

    // 5. Native `$EA` + mounted `FsOps::{symlink, setxattr, getxattr, listxattr, removexattr}`!
    engine
        .set_ea_at(&cx, f1, b"user.tag", b"v1", 0, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let f1_attr = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("obj1.bin"))
        .unwrap();
    assert_eq!(
        fs.getxattr(&cx, f1_attr.ino, "user.tag").unwrap(),
        Some(b"v1".to_vec())
    );
    fs.setxattr(
        &cx,
        &mut scope,
        f1_attr.ino,
        "user.extra",
        b"hello-ea",
        XattrSetMode::Create,
    )
    .unwrap();
    assert!(matches!(
        fs.setxattr(
            &cx,
            &mut scope,
            f1_attr.ino,
            "user.extra",
            b"dup",
            XattrSetMode::Create,
        ),
        Err(FfsError::Exists)
    ));
    let keys = fs.listxattr(&cx, f1_attr.ino).unwrap();
    assert_eq!(keys, vec!["user.extra".to_owned(), "user.tag".to_owned()]);
    assert!(
        fs.removexattr(&cx, &mut scope, f1_attr.ino, "user.tag")
            .unwrap()
    );
    assert_eq!(fs.getxattr(&cx, f1_attr.ino, "user.tag").unwrap(), None);

    // Mounted relative symlink creation + readlink round-trip!
    let sl = fs
        .symlink(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("fs_sym"),
            Path::new("dir/file.txt"),
            1000,
            1000,
        )
        .unwrap();
    assert_eq!(sl.kind, FileType::Symlink);
    assert_eq!(
        fs.readlink(&cx, &mut scope, sl.ino).unwrap(),
        b"dir/file.txt"
    );
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);

    // Whole-volume non-mutating check must be 100% clean (including active `$UsnJrnl` + reparse)!
    let chk = check_volume_device(
        &cx,
        Arc::clone(&dev) as Arc<dyn ByteDevice>,
        0,
        vol_bytes,
        NtfsCheckLimits::default(),
    )
    .unwrap();
    assert!(
        chk.is_clean(),
        "check failed after secondary metadata ops: {:?}",
        chk.issues
    );
}

#[test]
fn ntfs_efs_encrypt_raw_keyed_rw_decrypt_negative_controls_and_redaction() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xBD84_0006_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();

    let key = NtfsEfsKey::from_raw_bytes([0xA5; 32]);
    let wrong_key = NtfsEfsKey::from_raw_bytes([0x5A; 32]);
    let mut good_scope = StaticEfsKeyScope::new();
    good_scope.insert(key.clone());
    let mut bad_scope = StaticEfsKeyScope::new();
    bad_scope.insert(wrong_key);
    let empty_scope = StaticEfsKeyScope::new();

    // Redaction invariant: key bytes never appear in Debug or Display.
    assert!(!format!("{key:?}").contains("a5a5a5"));
    assert!(!format!("{key}").contains("a5a5a5"));

    let plaintext = b"TOP-SECRET-EFS-PAYLOAD-ACROSS-MULTIPLE-512B-SECTORS!".repeat(30); // 1560 bytes
    let f_ref = engine
        .create_file_at(&cx, root, &utf16("vault.bin"), &plaintext)
        .into_result()
        .unwrap();
    engine
        .encrypt_file_at(&cx, f_ref, &key, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();

    // 1. Unauthorized ordinary stream read & write MUST fail closed!
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/vault.bin").unwrap();
        assert!(matches!(
            vol.data_stream(&cx, &rec, &[]),
            Err(FfsError::UnsupportedFeature(_))
        ));
        let (_meta, info) = vol.efs_metadata(&cx, &rec).unwrap().unwrap();
        assert!(info.encrypted_flag_set && info.explicit_fek_profile);
        let (raw_sz, raw_cipher) = vol.read_raw_efs_ciphertext(&cx, &rec, 0, 2048).unwrap();
        assert_eq!(raw_sz, plaintext.len() as u64);
        assert_ne!(
            &raw_cipher[..plaintext.len()],
            plaintext.as_slice(),
            "ciphertext must not leak plaintext"
        );
        // Missing key and wrong key MUST return PermissionDenied!
        assert!(matches!(
            vol.read_efs_plaintext(&cx, &rec, &empty_scope, 0, 2048),
            Err(FfsError::PermissionDenied)
        ));
        assert!(matches!(
            vol.read_efs_plaintext(&cx, &rec, &bad_scope, 0, 2048),
            Err(FfsError::PermissionDenied)
        ));
        // Authorized scope decrypts exact bytes (including unaligned middle slice)!
        assert_eq!(
            vol.read_efs_plaintext(&cx, &rec, &good_scope, 0, 4096)
                .unwrap(),
            plaintext
        );
        assert_eq!(
            vol.read_efs_plaintext(&cx, &rec, &good_scope, 500, 120)
                .unwrap(),
            plaintext[500..620]
        );
    }
    assert!(matches!(
        engine.write_stream_range(&cx, f_ref, &[], 0, b"blocked"),
        NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
    ));
    assert!(matches!(
        engine.write_efs_stream_at(&cx, f_ref, &bad_scope, 0, b"nope", DEFAULT_NTFS_FILETIME),
        NtfsTxOutcome::NotCommitted(FfsError::PermissionDenied)
    ));

    // 2. Authorized keyed positioned write + decrypt round-trip!
    engine
        .write_efs_stream_at(
            &cx,
            f_ref,
            &good_scope,
            510,
            b"KEYED-SECTOR-CROSSING-UPDATE",
            DEFAULT_NTFS_FILETIME,
        )
        .into_result()
        .unwrap();
    let mut expected = plaintext;
    expected[510..538].copy_from_slice(b"KEYED-SECTOR-CROSSING-UPDATE");
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/vault.bin").unwrap();
        assert_eq!(
            vol.read_efs_plaintext(&cx, &rec, &good_scope, 0, 4096)
                .unwrap(),
            expected
        );
    }

    engine
        .decrypt_file_at(&cx, f_ref, &good_scope, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    assert_eq!(read_file_by_path(&cx, &engine, "/vault.bin"), expected);
    {
        let vol = engine.volume_view(&cx).unwrap();
        let rec = vol.resolve(&cx, "/vault.bin").unwrap();
        assert!(vol.efs_metadata(&cx, &rec).unwrap().is_none());
    }
    engine.check_clean_consistency(&cx).unwrap();
    let _ = EFS_STREAM_NAME;
    let _ = (DATA, REPARSE_POINT, SPARSE);
}

#[test]
fn ntfs_transforms_persistence_prefix_fault_cuts_and_cx_cancel() {
    let cx = Cx::for_testing();
    let (dev, vol_bytes) = format_to_fault_device(
        &cx,
        16,
        4096,
        NtfsFormatVersion::V3_1,
        0xBD84_0007_0000_0001,
    );
    let mut engine = open_clean_engine(&cx, &dev, vol_bytes);
    let root = engine.resolve_path_reference(&cx, "/").unwrap();
    let _ = engine
        .enable_usn_journal(&cx, 65_536, 4096, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    let f_ref = engine
        .create_file_at(&cx, root, &utf16("crash.bin"), &vec![b'Z'; 32 * 1024])
        .into_result()
        .unwrap();

    // Pre-cancelled Cx MUST fail without mutating backing storage!
    let before_cancel = dev.snapshot_durable_only();
    let cancelled_cx = Cx::for_testing();
    cancelled_cx.set_cancel_requested(true);
    assert!(matches!(
        engine.set_compression_at(&cancelled_cx, f_ref, true, DEFAULT_NTFS_FILETIME),
        NtfsTxOutcome::NotCommitted(FfsError::Cancelled)
    ));
    assert_eq!(dev.snapshot_durable_only(), before_cancel);

    // Fault-cut during LZNT1 compression transaction right after CommitLogFlush (winner redo)!
    let cut_snapshot: Arc<std::sync::Mutex<Option<Vec<u8>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let cap_dev = Arc::clone(&dev);
    let cap_slot = Arc::clone(&cut_snapshot);
    engine.set_stage_hook(Some(Box::new(move |stage| {
        if stage == NtfsPersistenceStage::CommitLogFlush {
            *cap_slot.lock().unwrap() = Some(cap_dev.snapshot_durable_only());
        }
        Ok(())
    })));
    engine
        .set_compression_at(&cx, f_ref, true, DEFAULT_NTFS_FILETIME)
        .into_result()
        .unwrap();
    engine.set_stage_hook(None);

    // Recover the torn post-commit cut image -> ARIES redo MUST complete the compression cleanly!
    let torn_img = cut_snapshot.lock().unwrap().take().expect("captured cut");
    let torn_dev = FaultInjectingNtfsDevice::new(torn_img);
    let recovered = NtfsTransactionEngine::from_device(
        &cx,
        Arc::clone(&torn_dev) as Arc<dyn ByteDevice>,
        0,
        vol_bytes,
        write_options_recover(),
    )
    .unwrap();
    recovered.check_clean_consistency(&cx).unwrap();
    assert_eq!(
        read_file_by_path(&cx, &recovered, "/crash.bin"),
        vec![b'Z'; 32 * 1024]
    );
    let _ = NtfsReference {
        record: 0,
        sequence: 0,
    };
}
