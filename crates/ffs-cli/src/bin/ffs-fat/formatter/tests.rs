mod native_layout;
mod populated_images;
mod publication;

use super::*;
use crate::{Cli, Command};
use clap::Parser;
use std::cell::{Cell, RefCell};
use std::os::unix::fs::symlink;

fn options(path: PathBuf, kind: FormatKind) -> FormatArgs {
    FormatArgs {
        image: path,
        kind,
        size_mib: match kind {
            FormatKind::Fat16 => 4,
            FormatKind::Fat32 => 33,
        },
        sectors_per_cluster: None,
        label: Some("frank data".into()),
        serial: Some(0x1234_ABCD),
        source_dir: None,
        sidecar: None,
    }
}

fn new_file(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
}

fn read_sector(file: &File, sector: u64) -> [u8; 512] {
    let mut bytes = [0_u8; 512];
    file.read_exact_at(&mut bytes, sector * 512).unwrap();
    bytes
}

fn short(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn long(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[test]
fn format_cli_requires_dialect_and_size_and_has_no_existing_image_switch() {
    let cli = Cli::try_parse_from([
        "ffs-fat",
        "format",
        "new.img",
        "--kind",
        "fat32",
        "--size-mib",
        "33",
        "--label",
        "data",
        "--serial",
        "305441741",
    ])
    .unwrap();
    let Command::Format { options } = cli.command else {
        panic!("expected format");
    };
    assert_eq!(options.kind, FormatKind::Fat32);
    assert_eq!(options.size_mib, 33);
    assert_eq!(options.serial, Some(0x1234_ABCD));
    assert_eq!(options.label.as_deref(), Some("data"));
    for missing in [
        vec!["ffs-fat", "format", "new.img"],
        vec!["ffs-fat", "format", "new.img", "--kind", "fat16"],
        vec!["ffs-fat", "format", "new.img", "--size-mib", "4"],
        vec![
            "ffs-fat",
            "format",
            "new.img",
            "--kind",
            "fat12",
            "--size-mib",
            "4",
        ],
    ] {
        assert!(Cli::try_parse_from(missing).is_err());
    }
    for extra in [
        vec!["--offset", "512"],
        vec!["--length", "4096"],
        vec!["--overwrite"],
        vec!["--device"],
        vec!["--rw"],
        vec!["--serial", "4294967296"],
        vec!["--size-mib", "18446744073709551616"],
    ] {
        let mut argv = vec![
            "ffs-fat",
            "format",
            "new.img",
            "--kind",
            "fat16",
            "--size-mib",
            "4",
        ];
        argv.extend(extra);
        assert!(Cli::try_parse_from(argv).is_err());
    }
}

#[test]
fn geometry_matches_independent_native_sector_counts_and_boundary_choices() {
    for (kind, mib, spc, fat, clusters, data) in [
        (FormatKind::Fat16, 3, 1, 24, 6063, 81),
        (FormatKind::Fat16, 4, 1, 32, 8095, 97),
        (FormatKind::Fat16, 16, 1, 127, 32_481, 287),
        (FormatKind::Fat16, 32, 1, 254, 64_995, 541),
        (FormatKind::Fat16, 33, 2, 132, 33_643, 297),
        (FormatKind::Fat16, 64, 2, 255, 65_264, 543),
        (FormatKind::Fat16, 1024, 32, 256, 65_518, 545),
        (FormatKind::Fat16, 2048, 128, 128, 32_765, 289),
        (FormatKind::Fat16, 4095, 128, 256, 65_515, 545),
        (FormatKind::Fat32, 33, 1, 520, 66_512, 1072),
        (FormatKind::Fat32, 64, 1, 1009, 129_022, 2050),
        (FormatKind::Fat32, 128, 1, 2017, 258_078, 4066),
        (FormatKind::Fat32, 4096, 1, 64_528, 8_259_520, 129_088),
        (FormatKind::Fat32, 524_352, 128, 65_537, 8_388_607, 131_106),
    ] {
        let layout = Layout::calculate(kind, mib).unwrap();
        assert_eq!(
            (
                layout.sectors_per_cluster,
                layout.fat_sectors,
                layout.data_clusters,
                layout.first_data_sector
            ),
            (spc, fat, clusters, data),
            "{kind:?} {mib} MiB"
        );
        let args = FormatArgs {
            image: PathBuf::from("not-created.img"),
            kind,
            size_mib: mib,
            sectors_per_cluster: None,
            label: None,
            serial: Some(0),
            source_dir: None,
            sidecar: None,
        };
        let plan = FormatPlan::prepare(&args).unwrap();
        let geometry = FatGeometry::parse(&plan.boot, layout.image_bytes()).unwrap();
        assert_eq!(geometry.cluster_count(), clusters);
        assert!(geometry.cluster_offset(clusters + 1).is_ok());
    }
    for (kind, mib) in [
        (FormatKind::Fat16, 0),
        (FormatKind::Fat16, 1),
        (FormatKind::Fat16, 2),
        (FormatKind::Fat16, 4096),
        (FormatKind::Fat32, 32),
        (FormatKind::Fat32, 524_353),
        (FormatKind::Fat32, 2_097_152),
        (FormatKind::Fat32, u64::MAX),
    ] {
        assert!(Layout::calculate(kind, mib).is_err(), "{kind:?} {mib}");
    }
}

#[test]
fn geometry_fat_capacity_matches_closed_form_across_size_transitions() {
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        for mib in (1..=4096).chain([32_768, 262_144, 524_288, 524_352]) {
            let Ok(layout) = Layout::calculate(kind, mib) else {
                continue;
            };
            let spc = u64::from(layout.sectors_per_cluster);
            let total = mib * 2048;
            let headers = kind.reserved_sectors() + kind.fixed_root_sectors();
            let entries_per_sector = 512 / u64::from(kind.native().entry_bytes());
            // Independent closed form for the smallest F satisfying
            // F*K >= floor((T-headers-2*F)/SPC)+2.
            let expected = (total - headers + spc) / (entries_per_sector * spc + 2) + 1;
            assert_eq!(u64::from(layout.fat_sectors), expected, "{kind:?} {mib}");
            assert!(
                u64::from(layout.fat_sectors) * entries_per_sector
                    >= u64::from(layout.data_clusters) + 2
            );
            assert!(u64::from(layout.first_data_sector) < total);
            assert!(layout.data_clusters as usize <= MAX_CHAIN_CLUSTERS);
        }
    }
}

#[test]
fn new_images_have_native_mirrors_roots_hints_labels_and_clean_readback() {
    let directory = tempfile::tempdir().unwrap();
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        let args = options(directory.path().join(format!("{kind:?}.img")), kind);
        let cx = Cx::for_testing();
        let report = create(&cx, &args).unwrap();
        assert_eq!(report["operation"], "create_new_image");
        assert_eq!(report["created_new_image"], true);
        assert_eq!(report["label"], "FRANK DATA");
        assert_eq!(report["serial"], 0x1234_ABCD_u32);
        assert_eq!(report["durability"], "file_and_parent_synced");
        assert_eq!(report["verification"]["complete"], true);
        assert_eq!(report["verification"]["read_only"], true);
        assert_eq!(report["verification"]["clean"], true);
        assert_eq!(report["verification"]["files"], 0);
        assert_eq!(report["verification"]["directories"], 1);
        assert_eq!(report["verification"]["lost_clusters"], 0);
        let file = File::open(&args.image).unwrap();
        assert_eq!(file.metadata().unwrap().len(), args.size_mib * 1_048_576);
        let boot = read_sector(&file, 0);
        assert_eq!(short(&boot, 11), 512);
        assert_eq!(boot[13], 1);
        assert_eq!(boot[16], 2);
        assert_eq!(boot[21], 0xF8);
        assert_eq!(short(&boot, 510), 0xAA55);
        assert_eq!(long(&boot, 28), 0);
        let (reserved, fat_sectors, root_sector, extension, clusters) = match kind {
            FormatKind::Fat16 => {
                assert_eq!(short(&boot, 14), 1);
                assert_eq!(short(&boot, 17), 512);
                assert_eq!(short(&boot, 19), 8192);
                assert_eq!(long(&boot, 32), 0);
                assert_eq!(short(&boot, 22), 32);
                assert_eq!(&boot[54..62], b"FAT16   ");
                (1, 32, 65, 36, 8095)
            }
            FormatKind::Fat32 => {
                assert_eq!(short(&boot, 14), 32);
                assert_eq!(short(&boot, 17), 0);
                assert_eq!(short(&boot, 19), 0);
                assert_eq!(short(&boot, 22), 0);
                assert_eq!(long(&boot, 32), 67_584);
                assert_eq!(long(&boot, 36), 520);
                assert_eq!(short(&boot, 40), 0);
                assert_eq!(short(&boot, 42), 0);
                assert_eq!(long(&boot, 44), 2);
                assert_eq!(short(&boot, 48), 1);
                assert_eq!(short(&boot, 50), 6);
                assert_eq!(&boot[82..90], b"FAT32   ");
                assert_eq!(boot, read_sector(&file, 6));
                let extension = read_sector(&file, 2);
                assert_eq!(extension, read_sector(&file, 8));
                assert_eq!(&extension[..510], &[0; 510]);
                assert_eq!(&extension[510..], &[0x55, 0xAA]);
                let info = read_sector(&file, 1);
                assert_eq!(info, read_sector(&file, 7));
                assert_eq!(long(&info, 0), 0x4161_5252);
                assert_eq!(long(&info, 484), 0x6141_7272);
                assert_eq!(long(&info, 488), 66_511);
                assert_eq!(long(&info, 492), 3);
                assert_eq!(long(&info, 508), 0xAA55_0000);
                assert!(info[4..484].iter().all(|byte| *byte == 0));
                (32, 520, 1072, 64, 66_512)
            }
        };
        assert_eq!(boot[extension], 0x80);
        assert_eq!(boot[extension + 1], 0);
        assert_eq!(boot[extension + 2], 0x29);
        assert_eq!(long(&boot, extension + 3), 0x1234_ABCD);
        assert_eq!(&boot[extension + 7..extension + 18], b"FRANK DATA ");
        // Check every byte of both FATs, including zero padding, independently
        // of the checker that only visits addressable data-cluster entries.
        for sector in 0..fat_sectors {
            let primary = read_sector(&file, reserved + sector);
            assert_eq!(primary, read_sector(&file, reserved + fat_sectors + sector));
            if sector == 0 {
                let header = match kind {
                    FormatKind::Fat16 => {
                        assert_eq!(short(&primary, 0), 0xFFF8);
                        assert_eq!(short(&primary, 2), 0xFFFF);
                        4
                    }
                    FormatKind::Fat32 => {
                        assert_eq!(long(&primary, 0), 0x0FFF_FFF8);
                        assert_eq!(long(&primary, 4), 0x0FFF_FFFF);
                        assert_eq!(long(&primary, 8), 0x0FFF_FFFF);
                        12
                    }
                };
                assert!(primary[header..].iter().all(|byte| *byte == 0));
            } else {
                assert_eq!(primary, [0; 512]);
            }
        }
        let root = read_sector(&file, root_sector);
        assert_eq!(&root[..11], b"FRANK DATA ");
        assert_eq!(root[11], 0x08);
        for offset in [16, 18, 24] {
            assert_eq!(short(&root, offset), 0x0021);
        }
        assert_eq!(long(&root, 28), 0);
        assert!(root[32..].iter().all(|byte| *byte == 0));
        assert_eq!(read_sector(&file, root_sector + 1), [0; 512]);
        assert_eq!(read_sector(&file, args.size_mib * 2048 - 1), [0; 512]);
        // create returned only after dropping every clone of the exclusive
        // lock, so the normal independently opened reader must now work.
        let volume = FatVolume::open(&cx, &args.image, 0, None).unwrap();
        assert!(
            volume
                .list(&cx, super::super::reader::Directory::Root)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            volume.free_clusters(&cx).unwrap(),
            clusters - u64::from(kind == FormatKind::Fat32)
        );
    }
}

#[test]
fn omitted_label_keeps_the_native_default_and_empty_root() {
    let directory = tempfile::tempdir().unwrap();
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        let mut args = options(directory.path().join(format!("{kind:?}.img")), kind);
        args.label = None;
        args.serial = Some(0);
        let report = create(&Cx::for_testing(), &args).unwrap();
        assert!(report["label"].is_null());
        assert_eq!(report["serial"], 0);
        let file = File::open(&args.image).unwrap();
        let boot = read_sector(&file, 0);
        let (extension, root) = match kind {
            FormatKind::Fat16 => (36, 65),
            FormatKind::Fat32 => (64, 1072),
        };
        assert_eq!(&boot[extension + 7..extension + 18], b"NO NAME    ");
        assert_eq!(read_sector(&file, root), [0; 512]);
    }
}

#[test]
fn invalid_options_and_cancelled_requests_never_create_an_output() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("must-not-exist.img");
    for label in [
        "",
        " ",
        " leading",
        "trailing ",
        "TOO-LONG-1234",
        "café",
        "A/B",
        "A\\B",
        "A.B",
        "A+B",
        "A,B",
        "A:B",
        "A;B",
        "A=B",
        "A?B",
        "A[B",
        "A]B",
        "A|B",
        "A<B",
        "A>B",
        "A\"B",
        "A*B",
        "A\0B",
        "A\u{7F}B",
    ] {
        let mut args = options(path.clone(), FormatKind::Fat16);
        args.label = Some(label.into());
        assert!(create(&Cx::for_testing(), &args).is_err(), "{label:?}");
        assert!(!path.exists());
    }
    for (kind, size_mib) in [
        (FormatKind::Fat16, 0),
        (FormatKind::Fat16, 2),
        (FormatKind::Fat16, 4096),
        (FormatKind::Fat32, 32),
        (FormatKind::Fat32, 524_353),
        (FormatKind::Fat32, u64::MAX),
    ] {
        let mut args = options(path.clone(), kind);
        args.size_mib = size_mib;
        assert!(create(&Cx::for_testing(), &args).is_err());
        assert!(!path.exists());
    }
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let error = create(&cx, &options(path.clone(), FormatKind::Fat16)).unwrap_err();
    assert!(matches!(
        error.downcast_ref::<FfsError>(),
        Some(FfsError::Cancelled)
    ));
    assert!(!path.exists());
}

#[test]
fn exclusive_creation_refuses_existing_files_directories_symlinks_and_devices() {
    let directory = tempfile::tempdir().unwrap();
    let cx = Cx::for_testing();
    let existing = directory.path().join("existing.img");
    for original in [b"".as_slice(), b"retain all existing bytes".as_slice()] {
        std::fs::write(&existing, original).unwrap();
        assert!(create(&cx, &options(existing.clone(), FormatKind::Fat16)).is_err());
        assert_eq!(std::fs::read(&existing).unwrap(), original);
    }
    assert!(
        create(
            &cx,
            &options(directory.path().to_owned(), FormatKind::Fat16)
        )
        .is_err()
    );
    let linked = directory.path().join("linked.img");
    symlink(&existing, &linked).unwrap();
    assert!(create(&cx, &options(linked.clone(), FormatKind::Fat16)).is_err());
    assert!(
        std::fs::symlink_metadata(&linked)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read(&existing).unwrap(),
        b"retain all existing bytes"
    );
    let absent = directory.path().join("absent.img");
    let dangling = directory.path().join("dangling.img");
    symlink(&absent, &dangling).unwrap();
    assert!(create(&cx, &options(dangling.clone(), FormatKind::Fat32)).is_err());
    assert!(!absent.exists());
    assert!(
        std::fs::symlink_metadata(&dangling)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(create(&cx, &options(PathBuf::from("/dev/null"), FormatKind::Fat16)).is_err());
    let sibling = directory.path().join("sibling.bin");
    std::fs::write(&sibling, b"neighbor").unwrap();
    let missing_parent = directory.path().join("missing").join("new.img");
    assert!(create(&cx, &options(missing_parent, FormatKind::Fat16)).is_err());
    assert_eq!(std::fs::read(sibling).unwrap(), b"neighbor");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Resize(u64),
    Write(u64),
    Flush,
    ParentSync,
}

struct FaultTarget {
    file: File,
    events: RefCell<Vec<Event>>,
    calls: Cell<usize>,
    fail_at: Option<usize>,
    cancel_at: Option<usize>,
    cx: Cx,
}

impl FaultTarget {
    fn event(&self, event: Event) -> io::Result<()> {
        let call = self.calls.get();
        self.calls.set(call + 1);
        self.events.borrow_mut().push(event);
        if self.cancel_at == Some(call) {
            self.cx.set_cancel_requested(true);
        }
        if self.fail_at == Some(call) {
            return Err(io::Error::other("injected creation I/O failure"));
        }
        Ok(())
    }
}

impl ImageTarget for FaultTarget {
    fn resize(&self, length: u64) -> io::Result<()> {
        self.event(Event::Resize(length))?;
        self.file.set_len(length)
    }

    fn write_sector(&self, offset: u64, bytes: &[u8; 512]) -> io::Result<()> {
        if let Err(error) = self.event(Event::Write(offset)) {
            // A real write_all_at can fail after writing a prefix. Preserve
            // that evidence and ensure it cannot produce a successful format.
            self.file.write_all_at(&bytes[..17], offset)?;
            return Err(error);
        }
        self.file.write_all_at(bytes, offset)
    }

    fn flush(&self) -> io::Result<()> {
        self.event(Event::Flush)?;
        self.file.sync_all()
    }
}

#[test]
fn every_initialization_io_failure_is_reported_and_keeps_the_new_file() {
    let directory = tempfile::tempdir().unwrap();
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        let args = options(directory.path().join("unused.img"), kind);
        let plan = FormatPlan::prepare(&args).unwrap();
        let publications = plan.publication_sectors().count();
        let first_publication = plan.before_boot.len() + 2;
        let primary_call = plan.before_boot.len() + publications + 1;
        let operations = plan.before_boot.len() + publications + 4;
        for fail_at in 0..operations {
            let path = directory
                .path()
                .join(format!("{kind:?}-failure-{fail_at}.img"));
            let cx = Cx::for_testing();
            let target = FaultTarget {
                file: new_file(&path),
                events: RefCell::new(Vec::new()),
                calls: Cell::new(0),
                fail_at: Some(fail_at),
                cancel_at: None,
                cx: cx.clone(),
            };
            let error =
                initialize(&cx, &target, &plan, || target.event(Event::ParentSync)).unwrap_err();
            let evidence = format!("{error:#}");
            assert!(evidence.contains("injected creation I/O failure"));
            if fail_at < first_publication {
                assert!(evidence.contains("incomplete before boot publication"));
            } else if fail_at < operations - 1 {
                assert!(evidence.contains("boot publication started"));
                assert!(evidence.contains("file durability is uncertain"));
            } else {
                assert!(evidence.contains("initialized and file-synchronized"));
                assert!(evidence.contains("parent-directory synchronization failed"));
                assert!(evidence.contains("directory durability is uncertain"));
            }
            assert!(path.is_file());
            assert_eq!(target.calls.get(), fail_at + 1);
            if fail_at == 0 {
                assert_eq!(target.file.metadata().unwrap().len(), 0);
            } else {
                assert_eq!(
                    target.file.metadata().unwrap().len(),
                    plan.layout.image_bytes()
                );
                let boot = read_sector(&target.file, 0);
                if fail_at <= primary_call {
                    assert_eq!(&boot[510..], &[0, 0]);
                } else {
                    assert_eq!(boot, plan.boot);
                }
                if kind == FormatKind::Fat32 {
                    let backup = read_sector(&target.file, 6);
                    if fail_at <= first_publication {
                        assert_eq!(&backup[510..], &[0, 0]);
                    } else {
                        assert_eq!(backup, plan.boot);
                    }
                }
            }
        }
    }
}

#[test]
fn initialization_is_bounded_orders_flush_before_boot_and_observes_mid_io_cancel() {
    let directory = tempfile::tempdir().unwrap();
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        let args = options(directory.path().join("unused.img"), kind);
        let plan = FormatPlan::prepare(&args).unwrap();
        let publications = plan.publication_sectors().count();
        let first_publication = plan.before_boot.len() + 2;
        let operations = plan.before_boot.len() + publications + 4;
        for cancel_at in 0..=operations {
            let path = directory
                .path()
                .join(format!("{kind:?}-cancel-{cancel_at}.img"));
            let cx = Cx::for_testing();
            let target = FaultTarget {
                file: new_file(&path),
                events: RefCell::new(Vec::new()),
                calls: Cell::new(0),
                fail_at: None,
                cancel_at: (cancel_at < operations).then_some(cancel_at),
                cx: cx.clone(),
            };
            let result = initialize(&cx, &target, &plan, || target.event(Event::ParentSync));
            assert!(path.is_file());
            if cancel_at < first_publication {
                let error = result.unwrap_err();
                assert!(matches!(
                    error.downcast_ref::<FfsError>(),
                    Some(FfsError::Cancelled)
                ));
                assert!(
                    error
                        .to_string()
                        .contains("incomplete before boot publication")
                );
                assert_eq!(target.calls.get(), cancel_at + 1);
                assert_eq!(&read_sector(&target.file, 0)[510..], &[0, 0]);
                if kind == FormatKind::Fat32 {
                    assert_eq!(&read_sector(&target.file, 6)[510..], &[0, 0]);
                }
            } else {
                result.unwrap();
                assert_eq!(target.calls.get(), operations);
                let events = target.events.borrow();
                assert_eq!(events[0], Event::Resize(plan.layout.image_bytes()));
                let mut suffix = vec![Event::Flush];
                if kind == FormatKind::Fat32 {
                    suffix.push(Event::Write(6 * 512));
                }
                suffix.extend([Event::Write(0), Event::Flush, Event::ParentSync]);
                assert_eq!(&events[events.len() - suffix.len()..], &suffix);
                assert!(events.len() <= 13);
                if cancel_at < operations {
                    // A pending request after publication cannot interrupt
                    // synchronization, but must stop the subsequent scan.
                    assert!(matches!(
                        verify_created(&cx, &target.file, &plan)
                            .unwrap_err()
                            .downcast_ref::<FfsError>(),
                        Some(FfsError::Cancelled)
                    ));
                    assert!(verify_created(&Cx::for_testing(), &target.file, &plan).is_ok());
                } else {
                    assert!(verify_created(&cx, &target.file, &plan).is_ok());
                }
            }
        }
    }
}

#[test]
fn readback_checks_backup_hints_labels_lengths_and_unplanned_fat_entries() {
    let directory = tempfile::tempdir().unwrap();
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        for scenario in 0..5 {
            let path = directory
                .path()
                .join(format!("{kind:?}-readback-{scenario}.img"));
            let args = options(path.clone(), kind);
            let plan = FormatPlan::prepare(&args).unwrap();
            let cx = Cx::for_testing();
            let file = new_file(&path);
            initialize(&cx, &file, &plan, || Ok(())).unwrap();
            match scenario {
                0 => file.set_len(plan.layout.image_bytes() - 1).unwrap(),
                1 => file
                    .write_all_at(b"X", plan.layout.root_sector() * 512)
                    .unwrap(),
                2 if kind == FormatKind::Fat32 => {
                    file.write_all_at(&[0], 7 * 512 + 488).unwrap();
                }
                2 => file.write_all_at(&[0], 39).unwrap(),
                3 if kind == FormatKind::Fat32 => {
                    file.write_all_at(&[0], 6 * 512 + 67).unwrap();
                }
                3 => file.write_all_at(&[0], 512).unwrap(),
                4 => {
                    // Cluster 300 is beyond the explicitly initialized header
                    // sector. Identical orphan allocation in both FATs must be
                    // found by the full checker, not the metadata comparison.
                    let (width, end) = match kind {
                        FormatKind::Fat16 => (2, 0xFFFF_u32.to_le_bytes()),
                        FormatKind::Fat32 => (4, 0x0FFF_FFFF_u32.to_le_bytes()),
                    };
                    for copy in 0..2 {
                        let offset = (kind.reserved_sectors()
                            + copy * u64::from(plan.layout.fat_sectors))
                            * 512
                            + 300 * width as u64;
                        file.write_all_at(&end[..width], offset).unwrap();
                    }
                }
                _ => unreachable!(),
            }
            let error = verify_created(&cx, &file, &plan).unwrap_err();
            if scenario == 4 {
                assert!(error.to_string().contains("empty-filesystem verification"));
            }
            assert!(path.is_file());
        }
    }
}

#[test]
fn verification_device_is_read_only_bounded_and_cancel_aware() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("new.img");
    let args = options(path.clone(), FormatKind::Fat16);
    let plan = FormatPlan::prepare(&args).unwrap();
    let cx = Cx::for_testing();
    let file = new_file(&path);
    file.try_lock().unwrap();
    initialize(&cx, &file, &plan, || Ok(())).unwrap();
    let device = CreatedImage {
        file: file.try_clone().unwrap(),
        length: plan.layout.image_bytes(),
    };
    assert!(matches!(
        device.write_all_at(&cx, ByteOffset(0), &[1]),
        Err(FfsError::ReadOnly)
    ));
    assert!(matches!(
        device.read_exact_at(&cx, ByteOffset(u64::MAX), &mut [0; 2]),
        Err(FfsError::InvalidGeometry(_))
    ));
    assert!(matches!(
        device.read_exact_at(&cx, ByteOffset(device.length), &mut [0; 1]),
        Err(FfsError::InvalidGeometry(_))
    ));
    assert!(verify_created(&cx, &file, &plan).is_ok());
    cx.set_cancel_requested(true);
    let mut untouched = [0xCC; 512];
    assert!(matches!(
        device.read_exact_at(&cx, ByteOffset(0), &mut untouched),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(untouched, [0xCC; 512]);
    assert!(matches!(
        verify_created(&cx, &file, &plan)
            .unwrap_err()
            .downcast_ref::<FfsError>(),
        Some(FfsError::Cancelled)
    ));
}
