//! Comprehensive integration, corruption, fault-cut, cancellation, and
//! source-drift tests for native NTFS 3.1 / 3.0 structural checking,
//! formatting, and source-preserving offline resize (`bd-h7cme`).

use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asupersync::Cx;
use asupersync::types::CancelKind;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_ntfs::formatter::{
    NtfsFormatOptions, NtfsFormatStage, NtfsFormatStageHook, NtfsFormatVersion, format_image_file,
};
use ffs_ntfs::reader::check::repair::{
    NtfsRepairAction, apply_bounded_repair, plan_bounded_repair,
};
use ffs_ntfs::reader::check::{
    NtfsCheckCategory, NtfsCheckLimits, NtfsCheckStatus, check_image_file,
};
use ffs_ntfs::resize::{
    NtfsResizeDirection, NtfsResizeOptions, NtfsResizeStage, NtfsResizeStageHook, plan_resize,
    run_resize,
};
use ffs_ntfs::{NtfsTransactionEngine, NtfsVolume, NtfsWriteOptions};
use ffs_ondisk::ntfs::NtfsGeometry;
use tempfile::tempdir;

fn file_blake3(path: &std::path::Path) -> String {
    let bytes = fs::read(path).expect("read file for blake3");
    blake3::hash(&bytes).to_hex().to_string()
}

#[test]
fn format_check_and_transaction_lifecycle_across_ntfs_31_and_30_geometries() {
    let cx = Cx::for_testing();
    let dir = tempdir().expect("tempdir");

    let configs: &[(&str, NtfsFormatVersion, u64, u32, u32)] = &[
        ("ntfs31_4k.img", NtfsFormatVersion::V3_1, 16, 512, 4096),
        ("ntfs31_512c.img", NtfsFormatVersion::V3_1, 8, 512, 512),
        ("ntfs31_64k.img", NtfsFormatVersion::V3_1, 16, 512, 65_536),
        ("ntfs31_4k_sec.img", NtfsFormatVersion::V3_1, 16, 4096, 4096),
        ("ntfs30_4k.img", NtfsFormatVersion::V3_0, 12, 512, 4096),
    ];

    for &(name, version, size_mib, sector_bytes, cluster_bytes) in configs {
        let img = dir.path().join(name);
        let mut opts = NtfsFormatOptions::new_image(img.clone(), size_mib);
        opts.version = version;
        opts.sector_bytes = sector_bytes;
        opts.cluster_bytes = Some(cluster_bytes);
        opts.label = Some(format!("LBL_{name}"));

        let report = format_image_file(&cx, &opts, None)
            .unwrap_or_else(|e| panic!("format {name} failed: {e}"));
        assert!(report.boot_published);
        assert!(report.check_clean);
        assert_eq!(report.ntfs_version, version.pair());
        assert_eq!(report.sector_bytes, sector_bytes);
        assert_eq!(report.cluster_bytes, cluster_bytes);

        let hash_before = file_blake3(&img);
        let chk = check_image_file(&cx, &img, 0, None, NtfsCheckLimits::default())
            .unwrap_or_else(|e| panic!("check {name} failed: {e}"));
        assert!(
            chk.clean,
            "{name} expected clean, got issues: {:?}",
            chk.issues
        );
        assert_eq!(chk.status, NtfsCheckStatus::Clean);
        assert_eq!(chk.ntfs_version, version.pair());
        assert_eq!(chk.write_calls, 0);
        assert_eq!(chk.sync_calls, 0);
        assert!(chk.backup_boot_present);
        assert_eq!(chk.backup_boot_matches, Some(true));
        assert_eq!(
            file_blake3(&img),
            hash_before,
            "check must never mutate image"
        );

        // Verify NtfsVolume opens both 3.0 and 3.1 natively and reads root directory.
        let vol = NtfsVolume::open(&cx, &img, 0, None)
            .unwrap_or_else(|e| panic!("NtfsVolume::open {name} failed: {e}"));
        assert_eq!(vol.version(), version.pair());
        let root = vol.record(&cx, 5, None).expect("read root");
        assert!(root.is_directory());
        let entries = vol.list_directory(&cx, &root).expect("list root");
        assert!(entries.len() >= 11, "expected system entries in root");
        drop(vol);

        // On NTFS 3.1, verify NtfsTransactionEngine admits cleanly and survives full CRUD + re-check!
        if version == NtfsFormatVersion::V3_1 && sector_bytes == 512 && cluster_bytes == 4096 {
            let mut engine = NtfsTransactionEngine::open(
                &cx,
                &img,
                0,
                None,
                NtfsWriteOptions {
                    offline_image: true,
                    allow_write: true,
                    recover_dirty: false,
                },
            )
            .expect("admit freshly formatted NTFS 3.1 image for native transactions");

            let created = engine
                .create_file(&cx, "/", "hello.txt", b"hello frankenfs native ntfs!")
                .into_result()
                .expect("create /hello.txt")
                .0;
            engine
                .mkdir(&cx, "/", "sub")
                .into_result()
                .expect("mkdir /sub");
            let big = vec![0xA5_u8; 64 * 1024];
            engine
                .create_file(&cx, "/sub", "data.bin", &big)
                .into_result()
                .expect("create 64 KiB /sub/data.bin");
            let _ = created;
            drop(engine);

            let chk_after = check_image_file(&cx, &img, 0, None, NtfsCheckLimits::default())
                .expect("re-check after transactions");
            assert!(
                chk_after.clean,
                "post-transaction check failed: {:?}",
                chk_after.issues
            );
        }
    }
}

#[test]
fn checker_detects_planted_corruptions_without_mutating_image_and_bounded_repair_works() {
    let cx = Cx::for_testing();
    let dir = tempdir().expect("tempdir");
    let img = dir.path().join("corrupt_test.img");
    let opts = NtfsFormatOptions::new_image(img.clone(), 12);
    format_image_file(&cx, &opts, None).expect("format base image");

    // 1. Corrupt trailing backup boot sector -> detected cleanly, non-mutating, eligible for bounded repair.
    let len = fs::metadata(&img).unwrap().len();
    {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&img)
            .unwrap();
        f.write_all_at(&[0xDE, 0xAD, 0xBE, 0xEF], len - 512)
            .unwrap();
        f.sync_all().unwrap();
    }
    let hash_before = file_blake3(&img);
    let report = check_image_file(&cx, &img, 0, None, NtfsCheckLimits::default()).expect("check");
    assert!(!report.clean);
    assert_eq!(report.status, NtfsCheckStatus::Corrupt);
    assert_eq!(report.backup_boot_matches, Some(false));
    assert_eq!(report.write_calls, 0);
    assert_eq!(report.sync_calls, 0);
    assert_eq!(file_blake3(&img), hash_before, "check must be non-mutating");

    let plan = plan_bounded_repair(&report);
    assert!(
        plan.eligible,
        "backup boot mismatch should be repair-eligible: {:?}",
        plan.refusal_reasons
    );
    assert!(
        plan.actions
            .iter()
            .any(|a| matches!(a, NtfsRepairAction::SyncBackupBootSector { .. }))
    );

    // Apply bounded repair with explicit authority and verify clean post-repair state.
    let (_applied_plan, after) =
        apply_bounded_repair(&cx, &img, 0, None, true, true, NtfsCheckLimits::default())
            .expect("apply bounded backup boot repair");
    assert!(
        after.clean,
        "post-repair check should be clean: {:?}",
        after.issues
    );
    assert_eq!(after.backup_boot_matches, Some(true));

    // 2. Plant free MFT slot marked IN_USE -> detected by checker AND refused by bounded repair!
    let mft_offset = {
        let vol = NtfsVolume::open(&cx, &img, 0, None).unwrap();
        vol.geometry
            .cluster_offset(vol.geometry.mft_cluster())
            .unwrap()
    };
    {
        // Slot 20 is free in $MFT::$BITMAP; write a bogus FILE header with IN_USE = 1.
        let mut fake = vec![0_u8; 1024];
        fake[0..4].copy_from_slice(b"FILE");
        fake[22..24].copy_from_slice(&1_u16.to_le_bytes());
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&img)
            .unwrap();
        f.write_all_at(&fake, mft_offset + 20 * 1024).unwrap();
        f.sync_all().unwrap();
    }
    let report2 = check_image_file(&cx, &img, 0, None, NtfsCheckLimits::default()).expect("check2");
    assert!(!report2.clean);
    assert_eq!(report2.free_slots_marked_in_use, 1);
    assert!(
        report2.issues.iter().any(
            |i| i.category == NtfsCheckCategory::MftSlot && i.code == "free_slot_marked_in_use"
        )
    );
    let plan2 = plan_bounded_repair(&report2);
    assert!(
        !plan2.eligible,
        "ambiguous free-slot IN_USE must be refused by bounded repair"
    );

    // 3. Plant `hiberfil.sys` on a fresh image -> checker reports hibernated and refuses repair.
    let hib_img = dir.path().join("hiber.img");
    format_image_file(
        &cx,
        &NtfsFormatOptions::new_image(hib_img.clone(), 12),
        None,
    )
    .unwrap();
    {
        let mut engine = NtfsTransactionEngine::open(
            &cx,
            &hib_img,
            0,
            None,
            NtfsWriteOptions {
                offline_image: true,
                allow_write: true,
                recover_dirty: false,
            },
        )
        .unwrap();
        engine
            .create_file(&cx, "/", "hiberfil.sys", b"")
            .into_result()
            .unwrap();
    }
    let hib_chk = check_image_file(&cx, &hib_img, 0, None, NtfsCheckLimits::default()).unwrap();
    assert!(!hib_chk.clean);
    assert!(hib_chk.hibernated);
    assert!(!plan_bounded_repair(&hib_chk).eligible);
}

#[test]
fn resize_grow_free_tail_shrink_relocate_shrink_and_slice_sentinel_preservation() {
    let cx = Cx::for_testing();
    let dir = tempdir().expect("tempdir");

    // Create 32 MiB NTFS 3.1 image and populate files, directories, and named ADS.
    let base_img = dir.path().join("src_32m.img");
    format_image_file(
        &cx,
        &NtfsFormatOptions::new_image(base_img.clone(), 32),
        None,
    )
    .expect("format 32 MiB");

    let payload_a: Vec<u8> = (0_u32..128 * 1024).map(|i| (i % 251) as u8).collect();
    let payload_ads = b"named-alternate-stream-payload-v1".to_vec();
    {
        let mut engine = NtfsTransactionEngine::open(
            &cx,
            &base_img,
            0,
            None,
            NtfsWriteOptions {
                offline_image: true,
                allow_write: true,
                recover_dirty: false,
            },
        )
        .expect("open 32 MiB for writes");
        engine.grow_mft(&cx, 64).into_result().unwrap();
        engine
            .create_file(&cx, "/", "alpha.bin", &payload_a)
            .into_result()
            .unwrap();
        let meta_u16: Vec<u16> = "meta".encode_utf16().collect();
        engine
            .create_file_stream(&cx, "/alpha.bin", &meta_u16, &payload_ads)
            .into_result()
            .unwrap();
        engine.mkdir(&cx, "/", "dir").into_result().unwrap();
        for i in 0..20 {
            let fname = format!("file_{i:02}.txt");
            engine
                .create_file(&cx, "/dir", &fname, format!("entry-{i:02}").as_bytes())
                .into_result()
                .unwrap();
        }
    }

    let src_hash = file_blake3(&base_img);

    // 1. Grow 32 MiB -> 48 MiB.
    let grown_img = dir.path().join("grown_48m.img");
    let grow_report = run_resize(
        &cx,
        &NtfsResizeOptions {
            source_image: base_img.clone(),
            source_offset: 0,
            source_length: None,
            output: grown_img.clone(),
            size_bytes: None,
            size_mib: Some(48),
            relocate: false,
            offline_image: true,
            dry_run: false,
        },
        None,
    )
    .expect("grow 32 MiB -> 48 MiB");
    assert_eq!(grow_report.plan.direction, NtfsResizeDirection::Grow);
    assert!(grow_report.boot_published);
    assert!(grow_report.check_clean);
    assert_eq!(
        file_blake3(&base_img),
        src_hash,
        "source must remain untouched"
    );

    // 2. Free-tail shrink 48 MiB -> 40 MiB without --relocate (should succeed because $MFTMirr is at 16 MiB < 40 MiB!).
    let free_shrunk = dir.path().join("shrunk_40m.img");
    let free_shrink_report = run_resize(
        &cx,
        &NtfsResizeOptions {
            source_image: grown_img,
            source_offset: 0,
            source_length: None,
            output: free_shrunk.clone(),
            size_bytes: None,
            size_mib: Some(40),
            relocate: false,
            offline_image: true,
            dry_run: false,
        },
        None,
    )
    .expect("free-tail shrink 48 MiB -> 40 MiB");
    assert_eq!(
        free_shrink_report.plan.direction,
        NtfsResizeDirection::Shrink
    );
    assert_eq!(free_shrink_report.plan.relocated_clusters, 0);

    // 3. Shrink 40 MiB -> 12 MiB WITHOUT --relocate MUST be refused (crosses $MFTMirr at ~16 MiB!).
    let refused_out = dir.path().join("refused_12m.img");
    let err = run_resize(
        &cx,
        &NtfsResizeOptions {
            source_image: free_shrunk.clone(),
            source_offset: 0,
            source_length: None,
            output: refused_out.clone(),
            size_bytes: None,
            size_mib: Some(12),
            relocate: false,
            offline_image: true,
            dry_run: false,
        },
        None,
    )
    .expect_err("shrink crossing $MFTMirr without --relocate must fail");
    assert!(
        matches!(err, FfsError::UnsupportedFeature(_)),
        "expected UnsupportedFeature refusal, got {err:?}"
    );
    assert!(
        !refused_out.exists(),
        "refused shrink must not create output"
    );

    // 4. Embed 40 MiB image inside a container with random prefix/suffix sentinels,
    //    then shrink 40 MiB -> 12 MiB WITH --relocate using --offset/--length!
    let sentinel_prefix: Vec<u8> = (0_u32..65_536).map(|i| ((i * 31) % 253) as u8).collect();
    let sentinel_suffix: Vec<u8> = (0_u32..65_536)
        .map(|i| ((i * 17 + 7) % 251) as u8)
        .collect();
    let container = dir.path().join("partition_container.img");
    let slice_bytes = fs::read(&free_shrunk).unwrap();
    let mut combined =
        Vec::with_capacity(sentinel_prefix.len() + slice_bytes.len() + sentinel_suffix.len());
    combined.extend_from_slice(&sentinel_prefix);
    combined.extend_from_slice(&slice_bytes);
    combined.extend_from_slice(&sentinel_suffix);
    fs::write(&container, &combined).unwrap();
    let container_hash = file_blake3(&container);

    let reloc_shrunk = dir.path().join("reloc_12m.img");
    let reloc_report = run_resize(
        &cx,
        &NtfsResizeOptions {
            source_image: container.clone(),
            source_offset: sentinel_prefix.len() as u64,
            source_length: Some(slice_bytes.len() as u64),
            output: reloc_shrunk.clone(),
            size_bytes: None,
            size_mib: Some(12),
            relocate: true,
            offline_image: true,
            dry_run: false,
        },
        None,
    )
    .expect("relocating shrink 40 MiB -> 12 MiB from partition slice");
    assert_eq!(reloc_report.plan.direction, NtfsResizeDirection::Shrink);
    assert!(
        reloc_report.plan.relocated_clusters > 0,
        "expected $MFTMirr relocation when shrinking 40 MiB -> 12 MiB"
    );
    assert_ne!(
        reloc_report.plan.old_mirror_cluster,
        reloc_report.plan.new_mirror_cluster
    );
    assert_eq!(
        file_blake3(&container),
        container_hash,
        "partition container and surrounding sentinels must be 100% untouched"
    );

    // Verify every file, ADS, directory entry, and full structural check on the relocated 12 MiB output!
    let final_chk = check_image_file(&cx, &reloc_shrunk, 0, None, NtfsCheckLimits::default())
        .expect("check relocated 12 MiB output");
    assert!(
        final_chk.clean,
        "relocated 12 MiB output failed check: {:?}",
        final_chk.issues
    );

    let vol = NtfsVolume::open(&cx, &reloc_shrunk, 0, None).expect("open relocated 12 MiB");
    let alpha = vol.resolve(&cx, "/alpha.bin").expect("resolve /alpha.bin");
    let alpha_stream = vol.data_stream(&cx, &alpha, &[]).expect("alpha data");
    let alpha_read = vol
        .read(&cx, &alpha_stream, 0, alpha_stream.size as usize)
        .expect("read alpha");
    assert_eq!(alpha_read, payload_a);

    let meta_name: Vec<u16> = "meta".encode_utf16().collect();
    let ads_stream = vol
        .data_stream(&cx, &alpha, &meta_name)
        .expect("alpha:meta");
    let ads_read = vol
        .read(&cx, &ads_stream, 0, ads_stream.size as usize)
        .expect("read ads");
    assert_eq!(ads_read, payload_ads);

    for i in 0..20 {
        let p = format!("/dir/file_{i:02}.txt");
        let rec = vol.resolve(&cx, &p).expect("resolve dir file");
        let st = vol.data_stream(&cx, &rec, &[]).expect("dir file data");
        let got = vol
            .read(&cx, &st, 0, st.size as usize)
            .expect("read dir file");
        assert_eq!(got, format!("entry-{i:02}").as_bytes());
    }
}

#[test]
fn format_and_resize_withhold_primary_vbr_on_every_pre_publication_cut_and_source_drift() {
    let dir = tempdir().expect("tempdir");

    // 1. Format cut matrix: inject I/O error at every pre-publication stage.
    let format_cut_stages = [
        NtfsFormatStage::SystemStreamsWritten,
        NtfsFormatStage::MftAndMirrorWritten,
        NtfsFormatStage::BackupBootWritten,
        NtfsFormatStage::PrePublishVerified,
    ];
    for (idx, &cut_stage) in format_cut_stages.iter().enumerate() {
        let cx = Cx::for_testing();
        let img = dir.path().join(format!("fmt_cut_{idx}.img"));
        let hook: NtfsFormatStageHook = Box::new(move |stage| {
            if stage == cut_stage {
                Err(FfsError::Io(std::io::Error::from_raw_os_error(
                    libc::ENOSPC,
                )))
            } else {
                Ok(())
            }
        });
        let err = format_image_file(
            &cx,
            &NtfsFormatOptions::new_image(img.clone(), 8),
            Some(&hook),
        )
        .expect_err("injected cut must fail format");
        assert!(matches!(err, FfsError::Io(_)));

        // Offset 0..512 MUST remain zeroed so NtfsGeometry::parse rejects partial output!
        let bytes = fs::read(&img).expect("read cut output");
        assert!(
            bytes[..512].iter().all(|&b| b == 0),
            "format cut at {cut_stage:?} leaked non-zero primary VBR bytes!"
        );
        assert!(NtfsGeometry::parse(&bytes[..512], bytes.len() as u64).is_err());
    }

    // 2. Resize cut matrix + Cx cancellation + source drift injection!
    let base_cx = Cx::for_testing();
    let src = dir.path().join("resize_cut_src.img");
    format_image_file(
        &base_cx,
        &NtfsFormatOptions::new_image(src.clone(), 16),
        None,
    )
    .unwrap();
    let src_hash = file_blake3(&src);

    let resize_cut_stages = [
        NtfsResizeStage::OutputCreated,
        NtfsResizeStage::ClustersCopied,
        NtfsResizeStage::RelocatedClustersWritten,
        NtfsResizeStage::MetadataRewritten,
        NtfsResizeStage::BackupBootWritten,
        NtfsResizeStage::PrePublishVerified,
    ];
    for (idx, &cut_stage) in resize_cut_stages.iter().enumerate() {
        let cx = Cx::for_testing();
        let out = dir.path().join(format!("resize_cut_{idx}.img"));
        let hook: NtfsResizeStageHook = Box::new(move |stage| {
            if stage == cut_stage {
                Err(FfsError::Io(std::io::Error::from_raw_os_error(
                    libc::ENOSPC,
                )))
            } else {
                Ok(())
            }
        });
        let err = run_resize(
            &cx,
            &NtfsResizeOptions {
                source_image: src.clone(),
                source_offset: 0,
                source_length: None,
                output: out.clone(),
                size_bytes: None,
                size_mib: Some(8),
                relocate: true,
                offline_image: true,
                dry_run: false,
            },
            Some(&hook),
        )
        .expect_err("injected cut must fail resize");
        assert!(matches!(err, FfsError::Io(_)));
        let bytes = fs::read(&out).expect("read cut resize output");
        assert!(
            bytes[..512].iter().all(|&b| b == 0),
            "resize cut at {cut_stage:?} leaked non-zero primary VBR!"
        );
        assert!(NtfsGeometry::parse(&bytes[..512], bytes.len() as u64).is_err());
        assert_eq!(file_blake3(&src), src_hash);
    }

    // 3. Cancellation via Cx::cancel_with mid-resize.
    {
        let cx = Cx::for_testing();
        let cancel_cx = cx.clone();
        let out = dir.path().join("resize_cancel.img");
        let hook: NtfsResizeStageHook = Box::new(move |stage| {
            if stage == NtfsResizeStage::ClustersCopied {
                cancel_cx.cancel_with(CancelKind::User, Some("test cancel"));
            }
            Ok(())
        });
        let err = run_resize(
            &cx,
            &NtfsResizeOptions {
                source_image: src.clone(),
                source_offset: 0,
                source_length: None,
                output: out.clone(),
                size_bytes: None,
                size_mib: Some(24),
                relocate: false,
                offline_image: true,
                dry_run: false,
            },
            Some(&hook),
        )
        .expect_err("cancelled resize must fail");
        assert!(matches!(err, FfsError::Cancelled));
        let bytes = fs::read(&out).unwrap();
        assert!(bytes[..512].iter().all(|&b| b == 0));
    }

    // 4. Uncooperative concurrent source mutation -> source-drift detection aborts before VBR publication!
    {
        let drift_src = dir.path().join("drift_src.img");
        fs::copy(&src, &drift_src).unwrap();
        let drift_path = drift_src.clone();
        let mutated = Arc::new(AtomicBool::new(false));
        let mutated_flag = Arc::clone(&mutated);
        let out = dir.path().join("drift_out.img");
        let hook: NtfsResizeStageHook = Box::new(move |stage| {
            if stage == NtfsResizeStage::MetadataRewritten
                && !mutated_flag.swap(true, Ordering::SeqCst)
            {
                // Mutate a byte in the source trailing sector to trigger SourceStamp/header digest drift!
                let f = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&drift_path)?;
                let len = f.metadata()?.len();
                f.write_all_at(&[0x55], len - 10)?;
                f.sync_all()?;
            }
            Ok(())
        });
        let err = run_resize(
            &base_cx,
            &NtfsResizeOptions {
                source_image: drift_src,
                source_offset: 0,
                source_length: None,
                output: out.clone(),
                size_bytes: None,
                size_mib: Some(24),
                relocate: false,
                offline_image: true,
                dry_run: false,
            },
            Some(&hook),
        )
        .expect_err("source drift must abort resize before primary VBR publication");
        assert!(
            matches!(err, FfsError::Corruption { .. }),
            "expected Corruption source-drift error, got {err:?}"
        );
        let bytes = fs::read(&out).unwrap();
        assert!(
            bytes[..512].iter().all(|&b| b == 0),
            "drifted resize must leave primary VBR unpublished"
        );
    }

    // 5. Dry-run plan_resize never creates output.
    let dry_out = dir.path().join("dry_run_never_created.img");
    let plan = plan_resize(
        &base_cx,
        &NtfsResizeOptions {
            source_image: src,
            source_offset: 0,
            source_length: None,
            output: dry_out.clone(),
            size_bytes: None,
            size_mib: Some(8),
            relocate: true,
            offline_image: true,
            dry_run: true,
        },
    )
    .expect("plan_resize dry-run");
    assert_eq!(plan.direction, NtfsResizeDirection::Shrink);
    assert!(!dry_out.exists());

    // Keep ByteDevice import active cleanly.
    let _ = std::any::type_name::<dyn ByteDevice>();
}
