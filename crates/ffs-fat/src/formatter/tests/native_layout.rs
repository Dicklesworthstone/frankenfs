use super::*;
use ffs_ondisk::fat::{FatDirectoryDecoder, FatEntry};
use std::collections::BTreeSet;

fn plan(kind: FormatKind, mib: u64, sectors: Option<u8>) -> FormatPlan {
    let mut args = options(PathBuf::from("not-created.img"), kind);
    args.size_mib = mib;
    args.sectors_per_cluster = sectors;
    args.label = Some("Data Disk".into());
    FormatPlan::prepare(&args).unwrap()
}

fn geometry(plan: &FormatPlan) -> FatGeometry {
    FatGeometry::parse(&plan.boot, plan.layout.image_bytes()).unwrap()
}

fn prepared(plan: &FormatPlan, sector: u64) -> &[u8; 512] {
    &plan
        .before_boot
        .iter()
        .find(|entry| entry.offset == sector * 512)
        .unwrap()
        .bytes
}

#[test]
fn fat16_golden_layout_is_independent_of_the_parser() {
    // 131072 total sectors - 1 reserved - 2*255 FAT - 32 root =
    // 130529 data sectors: 65264 clusters of two sectors, one tail sector.
    let plan = plan(FormatKind::Fat16, 64, None);
    let boot = &plan.boot;
    assert_eq!(&boot[..3], &[0xEB, 0x3C, 0x90]);
    assert_eq!(&boot[3..11], b"FRANKFS ");
    assert_eq!(short(boot, 11), 512);
    assert_eq!(boot[13], 2);
    assert_eq!(short(boot, 14), 1);
    assert_eq!(boot[16], 2);
    assert_eq!(short(boot, 17), 512);
    assert_eq!(short(boot, 19), 0);
    assert_eq!(boot[21], 0xF8);
    assert_eq!(short(boot, 22), 255);
    assert_eq!((short(boot, 24), short(boot, 26)), (63, 255));
    assert_eq!(long(boot, 28), 0);
    assert_eq!(long(boot, 32), 131_072);
    assert_eq!(&boot[36..39], &[0x80, 0, 0x29]);
    assert_eq!(&boot[39..43], &[0xCD, 0xAB, 0x34, 0x12]);
    assert_eq!(&boot[43..54], b"DATA DISK  ");
    assert_eq!(&boot[54..62], b"FAT16   ");
    assert_eq!(&boot[62..64], &[0xEB, 0xFE]);
    assert!(boot[64..510].iter().all(|byte| *byte == 0));
    assert_eq!(&boot[510..512], &[0x55, 0xAA]);

    let fat = prepared(&plan, 1);
    assert_eq!(&fat[..4], &[0xF8, 0xFF, 0xFF, 0xFF]);
    assert!(fat[4..].iter().all(|byte| *byte == 0));
    assert_eq!(fat, prepared(&plan, 256));
    assert_eq!(&prepared(&plan, 511)[..11], b"DATA DISK  ");
    let geometry = geometry(&plan);
    assert_eq!(geometry.fixed_root(), Some((511 * 512, 32 * 512)));
    assert_eq!(geometry.cluster_offset(2).unwrap(), 543 * 512);
    assert_eq!(geometry.cluster_count(), 65_264);
    assert_eq!(plan.layout.fat_sectors, 255);
    assert_eq!(
        plan.publication_sectors()
            .map(|entry| entry.offset)
            .collect::<Vec<_>>(),
        [0]
    );
}

#[test]
fn fat16_small_image_uses_the_16_bit_total_and_fixed_root() {
    let plan = plan(FormatKind::Fat16, 4, Some(1));
    let boot = &plan.boot;
    assert_eq!(short(boot, 19), 8192);
    assert_eq!(long(boot, 32), 0);
    assert_eq!(short(boot, 22), 32);
    let geometry = geometry(&plan);
    assert_eq!(geometry.cluster_count(), 8095);
    assert_eq!(geometry.fixed_root(), Some((65 * 512, 16_384)));
    assert_eq!(geometry.cluster_offset(2).unwrap(), 97 * 512);
    assert!(geometry.fs_info_sector().is_none());
    assert!(geometry.backup_boot_sector().is_none());
}

#[test]
fn fat32_golden_layout_has_native_three_sector_boot_copies_and_root() {
    // 131072 - 32 reserved - 2*1009 FAT = 129022 clusters.
    let plan = plan(FormatKind::Fat32, 64, None);
    let boot = &plan.boot;
    assert_eq!(&boot[..3], &[0xEB, 0x58, 0x90]);
    assert_eq!(short(boot, 11), 512);
    assert_eq!(boot[13], 1);
    assert_eq!(short(boot, 14), 32);
    assert_eq!(boot[16], 2);
    assert_eq!(
        (short(boot, 17), short(boot, 19), short(boot, 22)),
        (0, 0, 0)
    );
    assert_eq!(long(boot, 28), 0);
    assert_eq!(long(boot, 32), 131_072);
    assert_eq!(long(boot, 36), 1009);
    assert_eq!((short(boot, 40), short(boot, 42)), (0, 0));
    assert_eq!(long(boot, 44), 2);
    assert_eq!((short(boot, 48), short(boot, 50)), (1, 6));
    assert_eq!(&boot[52..64], &[0; 12]);
    assert_eq!(&boot[64..67], &[0x80, 0, 0x29]);
    assert_eq!(long(boot, 67), 0x1234_ABCD);
    assert_eq!(&boot[71..82], b"DATA DISK  ");
    assert_eq!(&boot[82..90], b"FAT32   ");
    assert_eq!(&boot[90..92], &[0xEB, 0xFE]);
    assert!(boot[92..510].iter().all(|byte| *byte == 0));
    assert_eq!(&boot[510..512], &[0x55, 0xAA]);

    let fat = prepared(&plan, 32);
    assert_eq!(long(fat, 0), 0x0FFF_FFF8);
    assert_eq!(long(fat, 4), 0x0FFF_FFFF);
    assert_eq!(long(fat, 8), 0x0FFF_FFFF);
    assert_eq!(FatKind::Fat32.decode_entry(long(fat, 8)), FatEntry::End);
    assert!(fat[12..].iter().all(|byte| *byte == 0));
    assert_eq!(fat, prepared(&plan, 1041));
    assert_eq!(&prepared(&plan, 2050)[..11], b"DATA DISK  ");
    let geometry = geometry(&plan);
    assert_eq!(geometry.cluster_count(), 129_022);
    assert_eq!(geometry.cluster_offset(2).unwrap(), 2050 * 512);
    assert!(geometry.fixed_root().is_none());

    let info = prepared(&plan, 1);
    assert_eq!(long(info, 0), 0x4161_5252);
    assert!(info[4..484].iter().all(|byte| *byte == 0));
    assert_eq!(long(info, 484), 0x6141_7272);
    assert_eq!(long(info, 488), 129_021);
    assert_eq!(long(info, 492), 3);
    assert_eq!(&info[496..508], &[0; 12]);
    assert_eq!(long(info, 508), 0xAA55_0000);
    assert_eq!(info, prepared(&plan, 7));
    for sector in [2, 8] {
        let extension = prepared(&plan, sector);
        assert!(extension[..510].iter().all(|byte| *byte == 0));
        assert_eq!(&extension[510..], &[0x55, 0xAA]);
    }
    let published = plan.publication_sectors().collect::<Vec<_>>();
    assert_eq!(
        published
            .iter()
            .map(|entry| entry.offset)
            .collect::<Vec<_>>(),
        [3072, 0]
    );
    assert_eq!(published[0].bytes, published[1].bytes);
    assert_eq!(
        FatGeometry::parse(&published[0].bytes, 64 * 1_048_576).unwrap(),
        geometry
    );
}

#[test]
fn root_contains_only_a_native_label_and_an_end_marker() {
    for kind in [FormatKind::Fat16, FormatKind::Fat32] {
        let plan = plan(kind, 64, None);
        let root = prepared(
            &plan,
            match kind {
                FormatKind::Fat16 => 511,
                FormatKind::Fat32 => 2050,
            },
        );
        assert_eq!(&root[..11], b"DATA DISK  ");
        assert_eq!(root[11], 0x08);
        for offset in [16, 18, 24] {
            assert_eq!(short(root, offset), 0x0021);
        }
        assert_eq!(&root[12..16], &[0; 4]);
        assert_eq!(&root[20..24], &[0; 4]);
        assert!(root[26..].iter().all(|byte| *byte == 0));
        let mut decoder = FatDirectoryDecoder::default();
        for slot in root.as_chunks::<32>().0 {
            assert!(decoder.push(slot, kind.native()).unwrap().is_none());
        }
        assert!(decoder.ended());
        assert!(!decoder.has_malformed_long_name());
    }
}

#[test]
fn sector_plans_are_unique_bounded_and_withhold_both_bpbs() {
    for (kind, mib) in [
        (FormatKind::Fat16, 3),
        (FormatKind::Fat16, 2047),
        (FormatKind::Fat16, 4095),
        (FormatKind::Fat32, 33),
        (FormatKind::Fat32, 32_768),
        (FormatKind::Fat32, 524_352),
    ] {
        let plan = plan(kind, mib, None);
        let mut offsets = BTreeSet::new();
        assert_eq!(
            plan.before_boot.len(),
            if kind == FormatKind::Fat16 { 3 } else { 7 }
        );
        assert_eq!(
            plan.publication_sectors().count(),
            if kind == FormatKind::Fat16 { 1 } else { 2 }
        );
        for entry in &plan.before_boot {
            assert_ne!(entry.offset, 0);
            if kind == FormatKind::Fat32 {
                assert_ne!(entry.offset, 6 * 512);
            }
            // Some prepared sectors have 55AA, but none is an admissible BPB.
            assert!(FatGeometry::parse(&entry.bytes, mib * 1_048_576).is_err());
        }
        for entry in plan.metadata_sectors() {
            assert!(
                offsets.insert(entry.offset),
                "two roles occupy sector {}",
                entry.offset / 512
            );
            assert_eq!(entry.offset % 512, 0);
            assert!(entry.offset + 512 <= mib * 1_048_576);
        }
        let geometry = geometry(&plan);
        let last = geometry
            .cluster_offset(geometry.cluster_count() + 1)
            .unwrap();
        assert!(last + u64::from(geometry.cluster_bytes()) <= mib * 1_048_576);
    }
}

#[test]
fn selected_fat_capacity_is_minimal_and_auto_clusters_stay_in_profile() {
    // Independent finite linear oracle complements the inherited closed-form
    // oracle and does not call the production binary-search algorithm.
    for (kind, sizes) in [
        (
            FormatKind::Fat16,
            &[
                3, 4, 16, 31, 32, 33, 64, 127, 128, 129, 1024, 2047, 2048, 4095,
            ][..],
        ),
        (
            FormatKind::Fat32,
            &[33, 64, 65, 128, 512, 1024, 4096, 8192, 32_768, 524_352][..],
        ),
    ] {
        for &mib in sizes {
            let plan = plan(kind, mib, None);
            let fixed = if kind == FormatKind::Fat16 { 33 } else { 32 };
            let total = mib * 2048;
            let spc = u64::from(plan.boot[13]);
            let width = u64::from(kind.native().entry_bytes());
            let expected = (1_u64..=(total - fixed) / 2)
                .find(|fat| fat * 512 >= ((total - fixed - 2 * fat) / spc + 2) * width)
                .unwrap();
            assert_eq!(
                u64::from(plan.layout.fat_sectors),
                expected,
                "{kind:?} {mib}"
            );
            let count = u64::from(plan.layout.data_clusters);
            match kind {
                FormatKind::Fat16 => assert!((4087..=65_518).contains(&count)),
                FormatKind::Fat32 => assert!((65_525..=8_388_608).contains(&count)),
            }
            assert!(geometry(&plan).cluster_bytes() <= 65_536);
        }
    }
    let large = plan(FormatKind::Fat32, 32_768, None);
    assert_eq!(large.boot[13], 8);
    assert_eq!(large.layout.fat_sectors, 65_409);
    assert_eq!(large.layout.data_clusters, 8_372_251);
    let large16 = plan(FormatKind::Fat16, 2047, None);
    assert_eq!(large16.boot[13], 64);
    assert_eq!(large16.layout.data_clusters, 65_495);
}

#[test]
fn unrepresentable_and_overflowing_requests_are_refused_before_emission() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("must-not-exist.img");
    for (kind, mib, spc) in [
        (FormatKind::Fat16, 0, None),
        (FormatKind::Fat16, 2, None),
        (FormatKind::Fat16, 4096, None),
        (FormatKind::Fat16, 64, Some(1)),
        (FormatKind::Fat16, 4, Some(2)),
        (FormatKind::Fat32, 32, None),
        (FormatKind::Fat32, 524_353, None),
        (FormatKind::Fat32, 64, Some(2)),
        (FormatKind::Fat32, 32_768, Some(1)),
        (FormatKind::Fat32, u64::MAX, None),
    ] {
        let mut args = options(path.clone(), kind);
        args.size_mib = mib;
        args.sectors_per_cluster = spc;
        assert!(
            create(&Cx::for_testing(), &args).is_err(),
            "unexpectedly admitted {kind:?} {mib} {spc:?}"
        );
        assert!(!path.exists());
    }
    for spc in [0, 3, 5, 63, 65, 255] {
        let mut args = options(path.clone(), FormatKind::Fat16);
        args.size_mib = 64;
        args.sectors_per_cluster = Some(spc);
        let error = create(&Cx::for_testing(), &args).unwrap_err();
        assert!(error.to_string().contains("power of two from 1 to 128"));
        assert!(!path.exists());
    }
}

#[test]
fn labels_and_serials_are_encoded_losslessly_with_a_declared_ascii_policy() {
    for (input, expected) in [
        ("a", *b"A          "),
        ("ab_cd-ef 09", *b"AB_CD-EF 09"),
        ("12345678901", *b"12345678901"),
        ("!#$%&'()-@", *b"!#$%&'()-@ "),
        ("^_{}~", *b"^_{}~      "),
    ] {
        for kind in [FormatKind::Fat16, FormatKind::Fat32] {
            let mut args = options(PathBuf::from("not-created.img"), kind);
            args.size_mib = 64;
            args.label = Some(input.into());
            args.serial = Some(u32::MAX);
            let plan = FormatPlan::prepare(&args).unwrap();
            assert_eq!(plan.label, Some(expected));
            assert_eq!(plan.serial, u32::MAX);
            let serial_offset = if kind == FormatKind::Fat16 { 39 } else { 67 };
            assert_eq!(long(&plan.boot, serial_offset), u32::MAX);
            assert_eq!(&plan.boot[serial_offset + 4..serial_offset + 15], &expected);
        }
    }
    for label in [
        "",
        " ",
        " edge",
        "edge ",
        "abcdefghijkl",
        "café",
        "bad/name",
        "bad\\name",
        "bad.name",
        "bad:name",
        "bad\0name",
        "bad\tname",
        "A*B",
    ] {
        let mut args = options(PathBuf::from("not-created.img"), FormatKind::Fat16);
        args.label = Some(label.into());
        assert!(
            FormatPlan::prepare(&args).is_err(),
            "unexpectedly admitted label {label:?}"
        );
    }
}
