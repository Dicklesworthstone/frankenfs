//! Comprehensive integration, corruption, fault-cut, cancellation, and
//! source-drift tests for native NTFS 3.1 / 3.0 structural checking,
//! formatting, and source-preserving offline resize (`bd-h7cme`).

use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use asupersync::types::CancelKind;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_ntfs::formatter::{
    NtfsFormatOptions, NtfsFormatStage, NtfsFormatStageHook, NtfsFormatVersion, format_device,
    format_image_file,
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
use ffs_ondisk::ntfs::{NtfsGeometry, ntfs_boot_sector_checksum};
use ffs_types::ByteOffset;
use tempfile::tempdir;

fn file_blake3(path: &std::path::Path) -> String {
    let bytes = fs::read(path).expect("read file for blake3");
    blake3::hash(&bytes).to_hex().to_string()
}

#[derive(Default, Debug)]
struct FormatProtectionState {
    depth: usize,
    completed: usize,
    aborted: usize,
    writes: usize,
    syncs: usize,
    unprotected_writes: usize,
    unprotected_syncs: usize,
    refuse: bool,
    fail_sync: Option<usize>,
}

struct FormatProtectionDevice {
    file: fs::File,
    bytes: u64,
    state: Mutex<FormatProtectionState>,
}

impl FormatProtectionDevice {
    fn create(path: &std::path::Path) -> Arc<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .expect("create format target");
        let bytes = 8 * 1024 * 1024;
        file.set_len(bytes).expect("size format target");
        Arc::new(Self {
            file,
            bytes,
            state: Mutex::new(FormatProtectionState::default()),
        })
    }
}

impl ByteDevice for FormatProtectionDevice {
    fn len_bytes(&self) -> u64 {
        self.bytes
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, data: &mut [u8]) -> ffs_error::Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        self.file.read_exact_at(data, offset.0)?;
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, data: &[u8]) -> ffs_error::Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let mut state = self.state.lock().unwrap();
        state.writes += 1;
        if state.depth == 0 {
            state.unprotected_writes += 1;
        }
        drop(state);
        self.file.write_all_at(data, offset.0)?;
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let mut state = self.state.lock().unwrap();
        state.syncs += 1;
        if state.depth == 0 {
            state.unprotected_syncs += 1;
        }
        if state.fail_sync == Some(state.syncs) {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::ENOSPC,
            )));
        }
        drop(state);
        self.file.sync_all()?;
        Ok(())
    }

    fn begin_durability_commit(&self, cx: &Cx) -> ffs_error::Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let mut state = self.state.lock().unwrap();
        if state.refuse {
            return Err(FfsError::ReadOnly);
        }
        state.depth += 1;
        Ok(())
    }

    fn complete_durability_commit(&self) {
        let mut state = self.state.lock().unwrap();
        assert!(state.depth > 0);
        state.depth -= 1;
        state.completed += 1;
    }

    fn abort_durability_commit(&self) {
        let mut state = self.state.lock().unwrap();
        assert!(state.depth > 0);
        state.depth -= 1;
        state.aborted += 1;
    }
}

#[test]
fn format_device_defers_protection_until_primary_boot_is_durable() {
    let cx = Cx::for_testing();
    let dir = tempdir().expect("tempdir");
    for nested in [false, true] {
        let image = dir.path().join(format!("protected_format_{nested}.img"));
        let device = FormatProtectionDevice::create(&image);
        let target: Arc<dyn ByteDevice> = device.clone();
        let opts = NtfsFormatOptions::new_image(image.clone(), 8);

        device.state.lock().unwrap().refuse = true;
        assert!(matches!(
            format_device(&cx, &target, &opts, None),
            Err(FfsError::ReadOnly)
        ));
        {
            let mut state = device.state.lock().unwrap();
            assert_eq!((state.writes, state.syncs, state.depth), (0, 0, 0));
            assert_eq!((state.completed, state.aborted), (0, 0));
            state.refuse = false;
        }
        if nested {
            device.begin_durability_commit(&cx).unwrap();
        }
        let observer = Arc::clone(&device);
        let hook: NtfsFormatStageHook = Box::new(move |stage| {
            let state = observer.state.lock().unwrap();
            let expected_depth =
                usize::from(nested) + usize::from(stage != NtfsFormatStage::TargetCreated);
            assert_eq!(state.depth, expected_depth, "stage {stage:?}");
            if stage == NtfsFormatStage::Synced {
                assert_eq!(state.syncs, 2);
                assert_eq!(state.completed, 0);
            }
            drop(state);
            if stage == NtfsFormatStage::PrePublishVerified {
                let mut primary_boot = [0_u8; 512];
                observer.file.read_exact_at(&mut primary_boot, 0)?;
                assert!(primary_boot.iter().all(|&b| b == 0));
            }
            Ok(())
        });
        let report = format_device(&cx, &target, &opts, Some(&hook)).expect("format target");
        assert!(report.boot_published && report.check_clean);
        {
            let state = device.state.lock().unwrap();
            assert_eq!(state.depth, usize::from(nested));
            assert_eq!((state.completed, state.aborted), (1, 0));
            assert!(state.writes > 2);
            assert_eq!(state.syncs, 2);
            assert_eq!((state.unprotected_writes, state.unprotected_syncs), (0, 0));
        }
        if nested {
            device.complete_durability_commit();
        }
        device.sync(&cx).expect("seal completed format");
        assert_eq!(device.state.lock().unwrap().unprotected_syncs, 1);
        assert!(
            check_image_file(&cx, &image, 0, None, NtfsCheckLimits::default())
                .expect("cold check completed format")
                .clean
        );
    }
}

#[test]
fn format_device_aborts_protection_on_failed_publication() {
    let cx = Cx::for_testing();
    let dir = tempdir().expect("tempdir");
    let cuts = [
        (Some(NtfsFormatStage::SystemStreamsWritten), None),
        (Some(NtfsFormatStage::MftAndMirrorWritten), None),
        (Some(NtfsFormatStage::BackupBootWritten), None),
        (Some(NtfsFormatStage::PrePublishVerified), None),
        (Some(NtfsFormatStage::PrimaryBootPublished), None),
        (Some(NtfsFormatStage::Synced), None),
        (None, Some(1)),
        (None, Some(2)),
    ];
    for (index, (cut_stage, fail_sync)) in cuts.into_iter().enumerate() {
        let image = dir
            .path()
            .join(format!("format_protection_cut_{index}.img"));
        let device = FormatProtectionDevice::create(&image);
        device.state.lock().unwrap().fail_sync = fail_sync;
        let target: Arc<dyn ByteDevice> = device.clone();
        let hook: NtfsFormatStageHook = Box::new(move |stage| {
            if Some(stage) == cut_stage {
                return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                    libc::ENOSPC,
                )));
            }
            Ok(())
        });
        assert!(
            format_device(
                &cx,
                &target,
                &NtfsFormatOptions::new_image(image, 8),
                Some(&hook),
            )
            .is_err(),
            "format must fail at {cut_stage:?}, sync {fail_sync:?}"
        );
        let state = device.state.lock().unwrap();
        assert_eq!(state.depth, 0);
        assert_eq!((state.completed, state.aborted), (0, 1));
        assert!(state.writes > 0);
        assert_eq!((state.unprotected_writes, state.unprotected_syncs), (0, 0));
    }
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
fn bounded_boot_repair_uses_the_volume_end_within_a_larger_container() {
    let cx = Cx::for_testing();
    let dir = tempdir().unwrap();
    let image = dir.path().join("volume.img");
    format_image_file(&cx, &NtfsFormatOptions::new_image(image.clone(), 8), None).unwrap();
    let volume = fs::read(image).unwrap();
    let prefix = [0xB5; 1024];
    let suffix = [0xDA; 1536];
    let base = prefix.len() as u64;
    let backup = volume.len() - 512;
    let container = dir.path().join("disk.img");
    let intact = [&prefix[..], &volume, &suffix[..]].concat();
    fs::write(&container, &intact).unwrap();

    let check = check_image_file(&cx, &container, base, None, NtfsCheckLimits::default()).unwrap();
    assert!(check.clean, "{:?}", check.issues);
    assert_eq!(check.backup_boot_offset, Some(backup as u64));

    let file = OpenOptions::new().write(true).open(&container).unwrap();
    file.write_all_at(&[0; 512], base + backup as u64).unwrap();
    drop(file);
    let (plan, after) = apply_bounded_repair(
        &cx,
        &container,
        base,
        None,
        true,
        true,
        NtfsCheckLimits::default(),
    )
    .unwrap();
    assert_eq!(
        plan.actions,
        vec![NtfsRepairAction::SyncBackupBootSector {
            backup_offset: backup as u64,
            sector_bytes: 512,
        }]
    );
    assert!(after.clean);
    assert_eq!(fs::read(container).unwrap(), intact);
}

#[test]
fn check_recognizes_cluster_rounded_boot_geometry_and_refuses_ambiguous_repair() {
    let cx = Cx::for_testing();
    let dir = tempdir().unwrap();
    let image = dir.path().join("rounded.img");
    format_image_file(&cx, &NtfsFormatOptions::new_image(image.clone(), 8), None).unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&image)
        .unwrap();
    let mut boot = [0; 512];
    file.read_exact_at(&mut boot, 0).unwrap();
    let backup = file.metadata().unwrap().len() - 512;
    let sectors_per_cluster = u64::from(boot[13]);
    let rounded_sectors = (backup / 512 / sectors_per_cluster) * sectors_per_cluster;
    assert!(rounded_sectors * 512 < backup);
    boot[40..48].copy_from_slice(&rounded_sectors.to_le_bytes());
    boot[80..84].fill(0);
    file.write_all_at(&boot, 0).unwrap();
    file.write_all_at(&boot, backup).unwrap();
    file.write_all_at(&[0xDB; 8192], backup + 512).unwrap();

    let check = check_image_file(&cx, &image, 0, None, NtfsCheckLimits::default()).unwrap();
    assert!(check.clean, "{:?}", check.issues);
    assert_eq!(check.backup_boot_offset, Some(backup));

    file.write_all_at(&[0; 512], backup).unwrap();
    drop(file);
    let before = file_blake3(&image);
    let check = check_image_file(&cx, &image, 0, None, NtfsCheckLimits::default()).unwrap();
    assert_eq!(check.backup_boot_offset, None);
    assert!(
        check
            .issues
            .iter()
            .any(|issue| issue.code == "backup_boot_location_ambiguous")
    );
    assert!(!plan_bounded_repair(&check).eligible);
    assert!(
        apply_bounded_repair(&cx, &image, 0, None, true, true, NtfsCheckLimits::default()).is_err()
    );
    assert_eq!(file_blake3(&image), before);
}

#[test]
fn resize_preserves_native_boot_code_and_optional_checksum() {
    let cx = Cx::for_testing();
    let dir = tempdir().unwrap();
    for (sector_bytes, checksummed) in [(512, true), (4096, false)] {
        let source = dir.path().join(format!("source-{sector_bytes}.img"));
        let mut format = NtfsFormatOptions::new_image(source.clone(), 16);
        format.sector_bytes = sector_bytes;
        format.cluster_bytes = Some(4096);
        format_image_file(&cx, &format, None).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .unwrap();
        let mut boot = vec![0; sector_bytes as usize];
        file.read_exact_at(&mut boot, 0).unwrap();
        boot[24..26].copy_from_slice(&17_u16.to_le_bytes()); // producer's BIOS geometry
        boot[68] = 0xF4; // alternate native encoding of a 4096-byte index block
        boot[84..510].fill(0xAB); // bootstrap code
        boot[512..].fill(0xCD);
        let checksum = if checksummed {
            ntfs_boot_sector_checksum(&boot).unwrap()
        } else {
            0
        };
        boot[80..84].copy_from_slice(&checksum.to_le_bytes());
        let source_end = file.metadata().unwrap().len();
        file.write_all_at(&boot, 0).unwrap();
        file.write_all_at(&boot, source_end - u64::from(sector_bytes))
            .unwrap();
        drop(file);

        let output = dir.path().join(format!("resized-{sector_bytes}.img"));
        let report = run_resize(
            &cx,
            &NtfsResizeOptions {
                source_image: source,
                source_offset: 0,
                source_length: None,
                output: output.clone(),
                size_bytes: None,
                size_mib: Some(6),
                relocate: true,
                offline_image: true,
                dry_run: false,
            },
            None,
        )
        .unwrap();
        assert_ne!(
            report.plan.new_mirror_cluster,
            report.plan.old_mirror_cluster
        );
        let file = fs::File::open(output).unwrap();
        let mut actual = vec![0; sector_bytes as usize];
        let expected_sectors = (6 * 1024 * 1024 / u64::from(sector_bytes)) - 1;
        boot[40..48].copy_from_slice(&expected_sectors.to_le_bytes());
        boot[48..56].copy_from_slice(&report.plan.new_mft_cluster.to_le_bytes());
        boot[56..64].copy_from_slice(&report.plan.new_mirror_cluster.to_le_bytes());
        if checksummed {
            let checksum = ntfs_boot_sector_checksum(&boot).unwrap();
            boot[80..84].copy_from_slice(&checksum.to_le_bytes());
        }
        for offset in [0, expected_sectors * u64::from(sector_bytes)] {
            file.read_exact_at(&mut actual, offset).unwrap();
            assert_eq!(actual, boot);
        }
    }
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
