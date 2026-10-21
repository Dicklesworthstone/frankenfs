//! Exercise slot growth through the production native rename entry points.
//! Formatter-backed image tests are not native-system interoperability proof.

use super::super::{find_entry_slots, rename_in_volume, unlink_in_volume};
use super::*;
use crate::reader::ImageArgs;
use crate::reader::replacement::{
    EXPECT_END, change_fat, create_in_volume, open_volume, set_hints, write_volume,
};
use clap::Parser as _;
use ffs_ondisk::fat::{FatKind, FatOemCodePage};

const NOW: u64 = 1_700_000_000;
const PAD: &str = "/Preceding removable native name.txt";
const SOURCE: &str = "/lower.txt";
const LONG: &str = "/A significantly longer native filename.bin";

fn fixture(kind: &str) -> (tempfile::TempDir, FatVolume) {
    let cx = Cx::for_testing();
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("slots.fat");
    let cli = crate::Cli::try_parse_from([
        "ffs-fat",
        "format",
        image.to_str().unwrap(),
        "--kind",
        kind,
        "--size-mib",
        if kind == "fat16" { "4" } else { "64" },
    ])
    .unwrap();
    let crate::Command::Format { options } = cli.command else {
        panic!("format options");
    };
    crate::formatter::create(&cx, &options).unwrap();
    let args = ImageArgs {
        image,
        offset: 0,
        length: None,
        oem_code_page: FatOemCodePage::Ascii,
        sidecar: None,
    };
    let volume = open_volume(&cx, &args, true).unwrap();
    create_in_volume(&cx, &volume, PAD, &[], NOW, false).unwrap();
    create_in_volume(&cx, &volume, SOURCE, b"retained payload", NOW, false).unwrap();
    (dir, volume)
}

fn empty_entry(index: usize) -> [u8; 32] {
    let mut entry = [0; 32];
    entry[..11].copy_from_slice(format!("F{index:07}TXT").as_bytes());
    entry[11] = 0x20;
    entry[24..26].copy_from_slice(&0x5821_u16.to_le_bytes());
    entry
}

fn fill_root(volume: &FatVolume) -> Vec<u64> {
    let cx = Cx::for_testing();
    let (offsets, _) = directory_offsets(&cx, volume, Directory::Root).unwrap();
    for (index, &offset) in offsets.iter().enumerate() {
        let raw = read_slot(&cx, volume, offset, false).unwrap();
        if matches!(raw.bytes[0], 0 | 0xE5) {
            write_volume(&cx, volume, offset, &empty_entry(index)).unwrap();
        }
    }
    volume.device.sync(&cx).unwrap();
    assert!(volume.check(&cx).unwrap().clean);
    offsets
}

fn check_source(volume: &FatVolume, path: &str, offset: u64, chain: &[u32]) {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, path).unwrap().unwrap();
    assert_eq!(entry.offset, offset);
    assert_eq!(entry.name().unwrap(), path.trim_start_matches('/'));
    let actual = volume.file_chain(&cx, &entry).unwrap();
    assert_eq!(actual.clusters, chain);
    assert_eq!(
        volume.read(&cx, &actual, 0, 64).unwrap(),
        b"retained payload"
    );
    let report = volume.check(&cx).unwrap();
    assert!(report.clean && report.complete && report.namespace_complete);
}

#[test]
fn longer_names_reuse_deleted_predecessors_on_full_fat_directories() {
    for kind in ["fat16", "fat32"] {
        let (dir, volume) = fixture(kind);
        let cx = Cx::for_testing();
        let offsets = fill_root(&volume);
        unlink_in_volume(&cx, &volume, PAD, false).unwrap();
        let entry = volume.resolve(&cx, SOURCE).unwrap().unwrap();
        let chain = volume.file_chain(&cx, &entry).unwrap();
        let original = read_slot(&cx, &volume, entry.offset, false).unwrap();
        let before = volume.check(&cx).unwrap();
        let image = dir.path().join("slots.fat");
        let bytes = std::fs::read(&image).unwrap();
        let dry = rename_in_volume(&cx, &volume, SOURCE, LONG, true).unwrap();
        assert_eq!(dry["new_entry_offset"], entry.offset);
        assert_eq!(std::fs::read(&image).unwrap(), bytes);
        let report = rename_in_volume(&cx, &volume, SOURCE, LONG, false).unwrap();
        assert_eq!(report["reused_source_slots"], true);
        assert_eq!(report["new_parent_directory_clusters"], 0);
        check_source(&volume, LONG, entry.offset, &chain.clusters);
        let after = volume.check(&cx).unwrap();
        assert_eq!(
            (after.free_clusters, after.allocated_clusters),
            (before.free_clusters, before.allocated_clusters)
        );
        assert_eq!(after.files, before.files);
        assert_eq!(
            directory_offsets(&cx, &volume, Directory::Root).unwrap().0,
            offsets
        );
        let raw = read_slot(&cx, &volume, entry.offset, false).unwrap();
        assert_eq!(raw.bytes[11], original.bytes[11]);
        assert_eq!(raw.bytes[13..], original.bytes[13..]);
        // End-to-end fresh reader, not merely the retained source-chain cache.
        drop(volume);
        let reopened = FatVolume::open(&cx, &image, 0, None).unwrap();
        check_source(&reopened, LONG, entry.offset, &chain.clusters);
    }
}

#[test]
fn mixed_case_sfn_to_lfn_can_grow_into_one_deleted_predecessor() {
    for kind in ["fat16", "fat32"] {
        let (_dir, volume) = fixture(kind);
        let cx = Cx::for_testing();
        fill_root(&volume);
        unlink_in_volume(&cx, &volume, PAD, false).unwrap();
        let entry = volume.resolve(&cx, SOURCE).unwrap().unwrap();
        let chain = volume.file_chain(&cx, &entry).unwrap();
        let mut original = read_slot(&cx, &volume, entry.offset, false).unwrap().bytes;
        original[12] |= 0x80;
        write_volume(&cx, &volume, entry.offset, &original).unwrap();
        volume.device.sync(&cx).unwrap();
        let before = volume.check(&cx).unwrap();
        let report = rename_in_volume(&cx, &volume, SOURCE, "/Lower.txt", false).unwrap();
        assert_eq!(report["case_only"], true);
        assert_eq!(report["new_entry_offset"], entry.offset);
        assert_eq!(report["new_directory_clusters"], 0);
        check_source(&volume, "/Lower.txt", entry.offset, &chain.clusters);
        let raw = read_slot(&cx, &volume, entry.offset, false).unwrap().bytes;
        assert_eq!(&raw[..12], &original[..12]);
        assert_eq!(raw[12] & !0x18, original[12] & !0x18);
        assert_eq!(raw[13..], original[13..]);
        assert_eq!(
            volume.check(&cx).unwrap().free_clusters,
            before.free_clusters
        );
        assert_eq!(
            volume.resolve(&cx, "/LOWER.TXT").unwrap().unwrap().offset,
            entry.offset
        );
    }
}

#[test]
fn failed_partial_reservation_does_not_modify_source_slots_or_backing() {
    let (dir, volume) = fixture("fat16");
    let cx = Cx::for_testing();
    fill_root(&volume);
    unlink_in_volume(&cx, &volume, PAD, false).unwrap();
    let entry = volume.resolve(&cx, SOURCE).unwrap().unwrap();
    // One reusable predecessor, then a live neighbor: insufficient for LONG.
    write_volume(&cx, &volume, entry.offset - 64, &empty_entry(900)).unwrap();
    volume.device.sync(&cx).unwrap();
    let (short, long) = find_entry_slots(&cx, &volume, Directory::Root, entry.offset).unwrap();
    assert!(long.is_empty());
    let before = std::fs::read(dir.path().join("slots.fat")).unwrap();
    assert!(
        reserve_before(&cx, &volume, Directory::Root, &short, &long, 4)
            .unwrap()
            .is_none()
    );
    assert!(long.is_empty());
    assert!(reserve_before(&cx, &volume, Directory::Root, &short, &long, 21).is_err());
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(reserve_before(&cancelled, &volume, Directory::Root, &short, &long, 1).is_err());
    assert!(rename_in_volume(&cx, &volume, SOURCE, LONG, false).is_err());
    assert_eq!(std::fs::read(dir.path().join("slots.fat")).unwrap(), before);
    assert!(volume.check(&cx).unwrap().clean);
}

#[test]
fn fat32_slot_growth_follows_a_backward_physical_directory_link() {
    let (_dir, volume) = fixture("fat32");
    let cx = Cx::for_testing();
    unlink_in_volume(&cx, &volume, PAD, false).unwrap();
    let source = volume.resolve(&cx, SOURCE).unwrap().unwrap();
    let old = read_slot(&cx, &volume, source.offset, false).unwrap();
    let chain = volume.file_chain(&cx, &source).unwrap();
    let root = volume.geometry.root_cluster();
    assert_eq!(root, 2);
    assert!(!chain.clusters.contains(&20) && !chain.clusters.contains(&40));
    let zeroes = vec![0; volume.geometry.cluster_bytes() as usize];
    for cluster in [20, 40] {
        write_volume(
            &cx,
            &volume,
            volume.cluster_offset(cluster).unwrap(),
            &zeroes,
        )
        .unwrap();
    }
    volume.device.sync(&cx).unwrap();
    change_fat(
        &cx,
        &volume,
        &[(root, EXPECT_END, 40), (20, 0, 0x0FFF_FFFF), (40, 0, 20)].into_iter(),
    )
    .unwrap();
    let moved = volume.cluster_offset(20).unwrap();
    write_volume(&cx, &volume, old.offset, &retired_slot(&old)).unwrap();
    write_volume(&cx, &volume, moved, &old.bytes).unwrap();
    set_hints(&cx, &volume, u32::MAX).unwrap();
    volume.device.sync(&cx).unwrap();
    let offsets = fill_root(&volume);
    let index = offsets.iter().position(|&at| at == moved).unwrap();
    for &at in &offsets[index - 4..index] {
        let slot = read_slot(&cx, &volume, at, false).unwrap();
        write_volume(&cx, &volume, at, &retired_slot(&slot)).unwrap();
        assert!(
            at > moved,
            "predecessors must reside at larger physical addresses"
        );
    }
    volume.device.sync(&cx).unwrap();
    let before = volume.check(&cx).unwrap();
    assert!(before.clean);
    let report = rename_in_volume(&cx, &volume, SOURCE, LONG, false).unwrap();
    assert_eq!(report["new_entry_offset"], moved);
    assert_eq!(report["reused_source_slots"], true);
    check_source(&volume, LONG, moved, &chain.clusters);
    assert_eq!(
        volume.check(&cx).unwrap().free_clusters,
        before.free_clusters
    );
    assert_eq!(volume.geometry.kind(), FatKind::Fat32);
}
