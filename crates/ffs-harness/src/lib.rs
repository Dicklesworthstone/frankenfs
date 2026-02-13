#![forbid(unsafe_code)]

pub mod e2e;

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
            CoverageDomain::new("ext4 metadata parsing", 10, 19),
            CoverageDomain::new("btrfs metadata parsing", 9, 20),
            CoverageDomain::new("MVCC/COW core", 5, 14),
            CoverageDomain::new("FUSE surface", 6, 12),
            CoverageDomain::new("self-healing durability policy", 5, 10),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseFixture {
    pub size: usize,
    pub writes: Vec<FixtureWrite>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureWrite {
    pub offset: usize,
    pub hex: String,
}

impl SparseFixture {
    /// Create a sparse fixture from raw bytes by extracting non-zero regions.
    ///
    /// Scans `data` for contiguous runs of non-zero bytes and records each run
    /// as a `FixtureWrite`. Zero-filled regions are omitted since the loader
    /// starts with an all-zero buffer.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut writes = Vec::new();
        let mut i = 0;
        while i < data.len() {
            // Skip zero bytes.
            if data[i] == 0 {
                i += 1;
                continue;
            }
            // Found a non-zero byte — scan for the end of the non-zero run.
            let start = i;
            while i < data.len() && data[i] != 0 {
                i += 1;
            }
            writes.push(FixtureWrite {
                offset: start,
                hex: hex::encode(&data[start..i]),
            });
        }
        Self {
            size: data.len(),
            writes,
        }
    }

    /// Create a sparse fixture from a byte range within a larger image.
    ///
    /// Extracts `data[offset..offset+len]` and adjusts write offsets so they
    /// are relative to the start of the extracted region.
    #[must_use]
    pub fn from_region(data: &[u8], offset: usize, len: usize) -> Self {
        let end = (offset + len).min(data.len());
        let region = &data[offset.min(data.len())..end];
        Self::from_bytes(region)
    }

    /// Round-trip: expand this fixture into a fully materialized byte buffer.
    pub fn materialize(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0_u8; self.size];
        for write in &self.writes {
            let payload = hex::decode(&write.hex)
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

/// Extract an ext4 superblock sparse fixture from a raw image.
///
/// Reads the 1024 bytes at offset 1024 (the ext4 superblock location),
/// validates it parses, and returns a `SparseFixture`.
pub fn extract_ext4_superblock(image: &[u8]) -> Result<SparseFixture> {
    let offset = ffs_types::EXT4_SUPERBLOCK_OFFSET;
    let size = ffs_types::EXT4_SUPERBLOCK_SIZE;
    if image.len() < offset + size {
        bail!(
            "image too small for ext4 superblock: need {} bytes, got {}",
            offset + size,
            image.len()
        );
    }
    // Validate it parses.
    let _sb = Ext4Superblock::parse_superblock_region(&image[offset..offset + size])
        .context("region does not contain a valid ext4 superblock")?;
    Ok(SparseFixture::from_bytes(&image[offset..offset + size]))
}

/// Extract a btrfs superblock sparse fixture from a raw image.
///
/// Reads the 4096 bytes at offset 65536 (the btrfs superblock location),
/// validates it parses, and returns a `SparseFixture`.
pub fn extract_btrfs_superblock(image: &[u8]) -> Result<SparseFixture> {
    let offset = ffs_types::BTRFS_SUPER_INFO_OFFSET;
    let size = ffs_types::BTRFS_SUPER_INFO_SIZE;
    if image.len() < offset + size {
        bail!(
            "image too small for btrfs superblock: need {} bytes, got {}",
            offset + size,
            image.len()
        );
    }
    let _sb = BtrfsSuperblock::parse_superblock_region(&image[offset..offset + size])
        .context("region does not contain a valid btrfs superblock")?;
    Ok(SparseFixture::from_bytes(&image[offset..offset + size]))
}

/// Extract a sparse fixture from an arbitrary byte range in an image.
///
/// This is the general-purpose version: specify `offset` and `len` to capture
/// any metadata structure (group descriptor, inode, directory block, etc.).
pub fn extract_region(image: &[u8], offset: usize, len: usize) -> Result<SparseFixture> {
    if offset.saturating_add(len) > image.len() {
        bail!(
            "region out of bounds: offset={offset} len={len} image_len={}",
            image.len()
        );
    }
    Ok(SparseFixture::from_bytes(&image[offset..offset + len]))
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

// ── Golden reference types ────────────────────────────────────────
//
// Versioned schema for kernel-derived golden outputs. The capture
// pipeline (scripts/capture_ext4_reference.sh) produces JSON in this
// format; conformance tests parse it and compare against ffs-ondisk.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenReference {
    pub version: u32,
    pub source: String,
    pub image_params: GoldenImageParams,
    pub superblock: GoldenSuperblock,
    pub directories: Vec<GoldenDirectory>,
    pub files: Vec<GoldenFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenImageParams {
    pub size_bytes: u64,
    pub block_size: u32,
    pub volume_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenSuperblock {
    pub block_size: u32,
    pub blocks_count: u64,
    pub inodes_count: u32,
    pub volume_name: String,
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenDirectory {
    pub path: String,
    pub entries: Vec<GoldenDirEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenDirEntry {
    pub name: String,
    pub file_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFile {
    pub path: String,
    pub size: u64,
    pub content: Vec<u8>,
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

    /// Parse a FEATURE_PARITY.md markdown table row into (domain, implemented, total).
    fn parse_parity_row(line: &str) -> Option<(String, u32, u32)> {
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        if cols.len() < 5 {
            return None;
        }
        let domain = cols[1].trim_start_matches("**").trim_end_matches("**");
        // Skip the "Overall" row — we check it separately
        if domain.eq_ignore_ascii_case("overall") {
            return None;
        }
        let implemented: u32 = cols[2]
            .trim_start_matches("**")
            .trim_end_matches("**")
            .parse()
            .ok()?;
        let total: u32 = cols[3]
            .trim_start_matches("**")
            .trim_end_matches("**")
            .parse()
            .ok()?;
        Some((domain.to_lowercase(), implemented, total))
    }

    // ── Fixture generation tests ──────────────────────────────────────

    #[test]
    fn sparse_fixture_from_bytes_round_trips() {
        let original = vec![0, 0, 0xAA, 0xBB, 0, 0, 0xCC, 0, 0];
        let fixture = SparseFixture::from_bytes(&original);
        assert_eq!(fixture.size, 9);
        assert_eq!(fixture.writes.len(), 2);
        assert_eq!(fixture.writes[0].offset, 2);
        assert_eq!(fixture.writes[0].hex, "aabb");
        assert_eq!(fixture.writes[1].offset, 6);
        assert_eq!(fixture.writes[1].hex, "cc");

        // Round-trip: materialize should produce identical bytes.
        let materialized = fixture.materialize().expect("materialize");
        assert_eq!(materialized, original);
    }

    #[test]
    fn sparse_fixture_from_bytes_all_zero() {
        let zeroes = vec![0_u8; 1024];
        let fixture = SparseFixture::from_bytes(&zeroes);
        assert_eq!(fixture.size, 1024);
        assert!(fixture.writes.is_empty());
        let materialized = fixture.materialize().expect("materialize");
        assert_eq!(materialized, zeroes);
    }

    #[test]
    fn sparse_fixture_from_bytes_all_nonzero() {
        let data = vec![0xFF_u8; 16];
        let fixture = SparseFixture::from_bytes(&data);
        assert_eq!(fixture.writes.len(), 1);
        assert_eq!(fixture.writes[0].offset, 0);
        assert_eq!(fixture.writes[0].hex, "ff".repeat(16));
    }

    #[test]
    fn sparse_fixture_json_round_trip() {
        let original = vec![0, 0x42, 0, 0, 0xDE, 0xAD, 0, 0];
        let fixture = SparseFixture::from_bytes(&original);
        let json = serde_json::to_string_pretty(&fixture).expect("serialize");
        let parsed: SparseFixture = serde_json::from_str(&json).expect("deserialize");
        let materialized = parsed.materialize().expect("materialize");
        assert_eq!(materialized, original);
    }

    #[test]
    fn extract_region_basic() {
        let data = vec![0, 0, 0xAA, 0xBB, 0xCC, 0, 0, 0, 0xDD, 0];
        let fixture = extract_region(&data, 2, 4).expect("extract_region");
        assert_eq!(fixture.size, 4);
        let materialized = fixture.materialize().expect("materialize");
        assert_eq!(materialized, vec![0xAA, 0xBB, 0xCC, 0]);
    }

    #[test]
    fn extract_region_out_of_bounds() {
        let data = vec![0; 10];
        assert!(extract_region(&data, 8, 5).is_err());
    }

    #[test]
    fn existing_fixture_round_trips_through_generation() {
        // Load an existing fixture, materialize it, generate a new fixture from
        // the materialized bytes, and verify the result is equivalent.
        let path = fixture_path("ext4_superblock_sparse.json");
        let original_data = load_sparse_fixture(&path).expect("load fixture");
        let generated = SparseFixture::from_bytes(&original_data);
        let regenerated_data = generated.materialize().expect("materialize");
        assert_eq!(original_data, regenerated_data);
    }

    #[test]
    fn parity_report_matches_feature_parity_md() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        let md_path = workspace_root.join("FEATURE_PARITY.md");
        let md_text = fs::read_to_string(&md_path).expect("read FEATURE_PARITY.md");

        // Parse all data rows from the Coverage Summary table
        let mut md_domains: Vec<(String, u32, u32)> = Vec::new();
        for line in md_text.lines() {
            if let Some(row) = parse_parity_row(line) {
                md_domains.push(row);
            }
        }
        assert!(
            !md_domains.is_empty(),
            "FEATURE_PARITY.md should have parseable coverage rows"
        );

        // Compare with ParityReport::current()
        let report = ParityReport::current();
        for domain in &report.domains {
            let key = domain.domain.to_lowercase();
            let md_match = md_domains.iter().find(|(d, _, _)| *d == key);
            assert!(
                md_match.is_some(),
                "FEATURE_PARITY.md missing domain: {}",
                domain.domain,
            );
            let (_, md_impl, md_total) = md_match.unwrap();
            assert_eq!(
                *md_impl, domain.implemented,
                "FEATURE_PARITY.md has implemented={md_impl} but ParityReport has {} for '{}'",
                domain.implemented, domain.domain,
            );
            assert_eq!(
                *md_total, domain.total,
                "FEATURE_PARITY.md has total={md_total} but ParityReport has {} for '{}'",
                domain.total, domain.domain,
            );
        }
    }
}
