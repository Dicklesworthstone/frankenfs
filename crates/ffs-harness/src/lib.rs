#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use ffs_ondisk::{
    BtrfsHeader, BtrfsItem, BtrfsSuperblock, Ext4DirEntry, Ext4GroupDesc, Ext4Inode,
    Ext4Superblock, map_logical_to_physical, parse_dir_block, parse_leaf_items,
    parse_sys_chunk_array,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageDomain {
    pub domain: String,
    pub implemented: u32,
    pub total: u32,
    pub coverage_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityReport {
    pub domains: Vec<CoverageDomain>,
    pub overall_implemented: u32,
    pub overall_total: u32,
    pub overall_coverage_percent: f64,
}

impl ParityReport {
    #[must_use]
    pub fn current() -> Self {
        let domains = vec![
            CoverageDomain::new("ext4 metadata parsing", 9, 19),
            CoverageDomain::new("btrfs metadata parsing", 7, 20),
            CoverageDomain::new("MVCC/COW core", 4, 14),
            CoverageDomain::new("FUSE surface", 6, 12),
            CoverageDomain::new("self-healing durability policy", 2, 10),
        ];

        let overall_implemented = domains.iter().map(|d| d.implemented).sum();
        let overall_total = domains.iter().map(|d| d.total).sum();
        let overall_coverage_percent = percentage(overall_implemented, overall_total);

        Self {
            domains,
            overall_implemented,
            overall_total,
            overall_coverage_percent,
        }
    }
}

impl CoverageDomain {
    #[must_use]
    pub fn new(domain: &str, implemented: u32, total: u32) -> Self {
        Self {
            domain: domain.to_owned(),
            implemented,
            total,
            coverage_percent: percentage(implemented, total),
        }
    }
}

#[must_use]
pub fn percentage(implemented: u32, total: u32) -> f64 {
    if total == 0 {
        0.0
    } else {
        (f64::from(implemented) / f64::from(total)) * 100.0
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SparseFixture {
    pub size: usize,
    pub writes: Vec<FixtureWrite>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FixtureWrite {
    pub offset: usize,
    pub hex: String,
}

pub fn load_sparse_fixture(path: &Path) -> Result<Vec<u8>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read fixture {}", path.display()))?;
    let fixture: SparseFixture = serde_json::from_str(&text)
        .with_context(|| format!("invalid fixture json {}", path.display()))?;

    let mut bytes = vec![0_u8; fixture.size];
    for write in fixture.writes {
        let payload = hex::decode(write.hex)
            .with_context(|| format!("invalid hex at offset {}", write.offset))?;

        let end = write
            .offset
            .checked_add(payload.len())
            .context("fixture offset overflow")?;
        if end > bytes.len() {
            bail!(
                "fixture write out of bounds: offset={} payload={} size={}",
                write.offset,
                payload.len(),
                bytes.len()
            );
        }

        bytes[write.offset..end].copy_from_slice(&payload);
    }

    Ok(bytes)
}

pub fn validate_ext4_fixture(path: &Path) -> Result<Ext4Superblock> {
    let data = load_sparse_fixture(path)?;
    Ext4Superblock::parse_superblock_region(&data)
        .with_context(|| format!("failed ext4 parse for fixture {}", path.display()))
}

pub fn validate_btrfs_fixture(path: &Path) -> Result<BtrfsSuperblock> {
    let data = load_sparse_fixture(path)?;
    BtrfsSuperblock::parse_superblock_region(&data)
        .with_context(|| format!("failed btrfs parse for fixture {}", path.display()))
}

pub fn validate_group_desc_fixture(path: &Path, desc_size: u16) -> Result<Ext4GroupDesc> {
    let data = load_sparse_fixture(path)?;
    Ext4GroupDesc::parse_from_bytes(&data, desc_size)
        .with_context(|| format!("failed group desc parse for fixture {}", path.display()))
}

pub fn validate_inode_fixture(path: &Path) -> Result<Ext4Inode> {
    let data = load_sparse_fixture(path)?;
    Ext4Inode::parse_from_bytes(&data)
        .with_context(|| format!("failed inode parse for fixture {}", path.display()))
}

pub fn validate_dir_block_fixture(path: &Path, block_size: u32) -> Result<Vec<Ext4DirEntry>> {
    let data = load_sparse_fixture(path)?;
    let (entries, _tail) = parse_dir_block(&data, block_size)
        .with_context(|| format!("failed dir block parse for fixture {}", path.display()))?;
    Ok(entries)
}

/// Validate a btrfs superblock fixture that contains a sys_chunk_array,
/// parse the chunk array, and map logical addresses to physical.
pub fn validate_btrfs_chunk_fixture(
    path: &Path,
) -> Result<(BtrfsSuperblock, Vec<ffs_ondisk::BtrfsChunkEntry>)> {
    let data = load_sparse_fixture(path)?;
    let sb = BtrfsSuperblock::parse_superblock_region(&data)
        .with_context(|| format!("failed btrfs parse for fixture {}", path.display()))?;
    let chunks = parse_sys_chunk_array(&sb.sys_chunk_array)
        .with_context(|| format!("failed chunk parse for fixture {}", path.display()))?;
    // Verify mapping is functional for root and chunk_root
    for (name, addr) in [("root", sb.root), ("chunk_root", sb.chunk_root)] {
        if addr != 0 {
            let _mapping = map_logical_to_physical(&chunks, addr).with_context(|| {
                format!(
                    "mapping {name} ({addr:#x}) failed for fixture {}",
                    path.display()
                )
            })?;
        }
    }
    Ok((sb, chunks))
}

/// Validate a btrfs leaf node fixture, returning the parsed header and items.
pub fn validate_btrfs_leaf_fixture(path: &Path) -> Result<(BtrfsHeader, Vec<BtrfsItem>)> {
    let data = load_sparse_fixture(path)?;
    let (header, items) = parse_leaf_items(&data)
        .with_context(|| format!("failed leaf parse for fixture {}", path.display()))?;
    header
        .validate(data.len(), None)
        .with_context(|| format!("header validation failed for fixture {}", path.display()))?;
    Ok((header, items))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(rel: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .join("conformance")
            .join("fixtures")
            .join(rel)
    }

    #[test]
    fn ext4_fixture_parses() {
        let path = fixture_path("ext4_superblock_sparse.json");
        let sb = validate_ext4_fixture(&path).expect("ext4 fixture parse");
        assert_eq!(sb.block_size, 4096);
        assert_eq!(sb.volume_name, "frankenfs");
    }

    #[test]
    fn btrfs_fixture_parses() {
        let path = fixture_path("btrfs_superblock_sparse.json");
        let sb = validate_btrfs_fixture(&path).expect("btrfs fixture parse");
        assert_eq!(sb.magic, ffs_types::BTRFS_MAGIC);
        assert_eq!(sb.label, "ffs-lab");
    }

    #[test]
    fn ext4_group_desc_32byte_fixture_parses() {
        let path = fixture_path("ext4_group_desc_32byte.json");
        let gd = validate_group_desc_fixture(&path, 32).expect("group desc 32 parse");
        assert_eq!(gd.block_bitmap, 5);
        assert_eq!(gd.inode_bitmap, 6);
        assert_eq!(gd.inode_table, 7);
        assert_eq!(gd.free_blocks_count, 200);
        assert_eq!(gd.free_inodes_count, 1000);
        assert_eq!(gd.used_dirs_count, 3);
        assert_eq!(gd.itable_unused, 500);
        assert_eq!(gd.flags, 4);
        assert_eq!(gd.checksum, 0xCDAB);
    }

    #[test]
    fn ext4_group_desc_64byte_fixture_parses() {
        let path = fixture_path("ext4_group_desc_64byte.json");
        let gd = validate_group_desc_fixture(&path, 64).expect("group desc 64 parse");
        // Low 32 bits = 5, high 32 bits = 1 → 0x1_0000_0005
        assert_eq!(gd.block_bitmap, 0x1_0000_0005);
        assert_eq!(gd.inode_bitmap, 0x2_0000_0006);
        assert_eq!(gd.inode_table, 0x3_0000_0007);
        // Low 16 bits = 200 (0xC8), high 16 bits = 10 (0x0A) → 0x000A_00C8
        assert_eq!(gd.free_blocks_count, 0x000A_00C8);
        assert_eq!(gd.free_inodes_count, 0x0014_03E8);
        assert_eq!(gd.used_dirs_count, 0x0005_0003);
        assert_eq!(gd.itable_unused, 0x0064_01F4);
    }

    #[test]
    fn ext4_inode_regular_file_fixture_parses() {
        let path = fixture_path("ext4_inode_regular_file.json");
        let inode = validate_inode_fixture(&path).expect("regular file inode parse");
        assert_eq!(inode.mode, 0o10_0644);
        assert_eq!(inode.uid, 1000);
        assert_eq!(inode.size, 1024);
        assert_eq!(inode.links_count, 1);
        assert_eq!(inode.blocks, 8);
        assert_eq!(inode.flags, 0x0008_0000); // EXTENTS_FL
        assert_eq!(inode.generation, 42);
        assert_eq!(inode.extent_bytes.len(), 60);
    }

    #[test]
    fn ext4_inode_directory_fixture_parses() {
        let path = fixture_path("ext4_inode_directory.json");
        let inode = validate_inode_fixture(&path).expect("directory inode parse");
        assert_eq!(inode.mode, 0o4_0755);
        assert_eq!(inode.size, 4096);
        assert_eq!(inode.links_count, 2);
        assert_eq!(inode.flags, 0x0008_0000); // EXTENTS_FL
    }

    #[test]
    fn ext4_dir_block_fixture_parses() {
        let path = fixture_path("ext4_dir_block.json");
        let entries = validate_dir_block_fixture(&path, 4096).expect("dir block parse");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name_str(), ".");
        assert_eq!(entries[0].inode, 2);
        assert_eq!(entries[1].name_str(), "..");
        assert_eq!(entries[1].inode, 2);
        assert_eq!(entries[2].name_str(), "hello.txt");
        assert_eq!(entries[2].inode, 11);
    }

    #[test]
    fn btrfs_chunk_fixture_parses() {
        let path = fixture_path("btrfs_superblock_with_chunks.json");
        let (sb, chunks) = validate_btrfs_chunk_fixture(&path).expect("btrfs chunk fixture parse");
        assert_eq!(sb.magic, ffs_types::BTRFS_MAGIC);
        assert_eq!(sb.label, "ffs-chunks");
        assert_eq!(sb.sys_chunk_array_size, 97);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].key.objectid, 256);
        assert_eq!(chunks[0].key.item_type, 228);
        assert_eq!(chunks[0].length, 8 * 1024 * 1024);
        assert_eq!(chunks[0].stripes[0].devid, 1);
        assert_eq!(chunks[0].stripes[0].offset, 0x10_0000);
    }

    #[test]
    fn btrfs_chunk_mapping_covers_root() {
        let path = fixture_path("btrfs_superblock_with_chunks.json");
        let (sb, chunks) = validate_btrfs_chunk_fixture(&path).expect("btrfs chunk fixture parse");
        // root=0x4000 is within chunk [0, 8MiB), mapped to physical [1MiB, 9MiB)
        let mapping = ffs_ondisk::map_logical_to_physical(&chunks, sb.root)
            .expect("mapping ok")
            .expect("root should be covered");
        assert_eq!(mapping.devid, 1);
        assert_eq!(mapping.physical, 0x10_0000 + sb.root);
    }

    #[test]
    fn btrfs_leaf_fixture_parses() {
        let path = fixture_path("btrfs_leaf_node.json");
        let (header, items) = validate_btrfs_leaf_fixture(&path).expect("btrfs leaf fixture parse");
        assert_eq!(header.level, 0);
        assert_eq!(header.nritems, 3);
        assert_eq!(header.owner, 5);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].key.objectid, 256);
        assert_eq!(items[0].key.item_type, 1);
        assert_eq!(items[1].key.objectid, 256);
        assert_eq!(items[1].key.item_type, 12);
        assert_eq!(items[2].key.objectid, 257);
        assert_eq!(items[2].key.item_type, 1);
    }

    #[test]
    fn parity_report_is_non_zero() {
        let report = ParityReport::current();
        assert!(report.overall_total > 0);
        assert!(report.overall_implemented > 0);
        assert!(report.overall_coverage_percent > 0.0);
    }
}
