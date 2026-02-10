#![forbid(unsafe_code)]

use ffs_harness::{
    ParityReport, validate_btrfs_chunk_fixture, validate_btrfs_fixture,
    validate_btrfs_leaf_fixture, validate_dir_block_fixture, validate_ext4_fixture,
    validate_group_desc_fixture, validate_inode_fixture,
};
use std::path::Path;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance")
        .join("fixtures")
        .join(name)
}

#[test]
fn ext4_and_btrfs_fixtures_conform() {
    let ext4_sparse = validate_ext4_fixture(&fixture_path("ext4_superblock_sparse.json"))
        .expect("ext4 sparse fixture");
    let ext4_mkfs = validate_ext4_fixture(&fixture_path("ext4_superblock_mkfs_4096.json"))
        .expect("ext4 mkfs fixture");
    let btrfs = validate_btrfs_fixture(&fixture_path("btrfs_superblock_sparse.json"))
        .expect("btrfs fixture");

    assert_eq!(ext4_sparse.block_size, 4096);
    assert_eq!(ext4_mkfs.block_size, 4096);
    assert_eq!(ext4_mkfs.log_cluster_size, 2);
    assert_eq!(ext4_mkfs.cluster_size, 4096);
    assert_eq!(ext4_mkfs.blocks_per_group, ext4_mkfs.clusters_per_group);
    assert_eq!(ext4_mkfs.volume_name, "ffs-mkfs");
    assert_eq!(btrfs.sectorsize, 4096);
}

#[test]
fn ext4_group_desc_fixtures_conform() {
    let gd32 = validate_group_desc_fixture(&fixture_path("ext4_group_desc_32byte.json"), 32)
        .expect("32-byte group desc");
    assert_eq!(gd32.block_bitmap, 5);
    assert_eq!(gd32.inode_bitmap, 6);
    assert_eq!(gd32.inode_table, 7);
    assert_eq!(gd32.free_blocks_count, 200);

    let gd64 = validate_group_desc_fixture(&fixture_path("ext4_group_desc_64byte.json"), 64)
        .expect("64-byte group desc");
    assert!(
        gd64.block_bitmap > u64::from(u32::MAX),
        "64-bit path should set high bits"
    );
}

#[test]
fn ext4_inode_fixtures_conform() {
    let file_inode = validate_inode_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("regular file inode");
    assert_eq!(
        file_inode.mode & 0o17_0000,
        0o10_0000,
        "should be regular file"
    );
    assert_eq!(file_inode.size, 1024);

    let dir_inode = validate_inode_fixture(&fixture_path("ext4_inode_directory.json"))
        .expect("directory inode");
    assert_eq!(dir_inode.mode & 0o17_0000, 0o4_0000, "should be directory");
    assert_eq!(dir_inode.links_count, 2);
}

#[test]
fn ext4_dir_block_fixture_conforms() {
    let entries =
        validate_dir_block_fixture(&fixture_path("ext4_dir_block.json"), 4096).expect("dir block");
    assert!(entries.len() >= 3, "should have at least 3 entries");
    assert!(entries.iter().any(|e| e.name_str() == "hello.txt"));
}

#[test]
fn btrfs_chunk_mapping_fixture_conforms() {
    let (sb, chunks) =
        validate_btrfs_chunk_fixture(&fixture_path("btrfs_superblock_with_chunks.json"))
            .expect("btrfs chunk fixture");
    assert!(!chunks.is_empty(), "should have at least one chunk entry");
    // root and chunk_root should be mappable
    let root_map = ffs_ondisk::map_logical_to_physical(&chunks, sb.root)
        .expect("mapping ok")
        .expect("root covered");
    assert_eq!(root_map.devid, 1);
    let cr_map = ffs_ondisk::map_logical_to_physical(&chunks, sb.chunk_root)
        .expect("mapping ok")
        .expect("chunk_root covered");
    assert_eq!(cr_map.devid, 1);
}

#[test]
fn btrfs_leaf_fixture_conforms() {
    let (header, items) = validate_btrfs_leaf_fixture(&fixture_path("btrfs_leaf_node.json"))
        .expect("btrfs leaf fixture");
    assert_eq!(header.level, 0, "should be a leaf");
    assert!(items.len() >= 3, "should have at least 3 items");
    // Items should be sorted by key (objectid then type)
    for pair in items.windows(2) {
        let a = &pair[0].key;
        let b = &pair[1].key;
        assert!(
            (a.objectid, a.item_type) <= (b.objectid, b.item_type),
            "items should be sorted by key"
        );
    }
}

#[test]
fn parity_report_totals_are_consistent() {
    let report = ParityReport::current();
    let implemented_sum: u32 = report.domains.iter().map(|d| d.implemented).sum();
    let total_sum: u32 = report.domains.iter().map(|d| d.total).sum();

    assert_eq!(implemented_sum, report.overall_implemented);
    assert_eq!(total_sum, report.overall_total);
}
