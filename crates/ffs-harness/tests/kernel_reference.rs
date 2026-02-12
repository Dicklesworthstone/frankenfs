#![forbid(unsafe_code)]
//! End-to-end conformance: compare ffs-ondisk ext4 parsing against
//! Linux kernel ext4 tools (`mkfs.ext4`, `debugfs`, `dumpe2fs`).
//!
//! **Strategy:**
//! 1. Generate a small ext4 image at test time via `mkfs.ext4`.
//! 2. Populate it with known files and directories via `debugfs -w`.
//! 3. Capture the kernel's view of the image via `dumpe2fs -h` and `debugfs`.
//! 4. Parse the same raw image bytes with `ffs_ondisk::Ext4ImageReader`.
//! 5. Compare: ffs-ondisk output must match kernel tool output for all
//!    tested behaviors (superblock, directory listing, inode metadata,
//!    file content).
//!
//! Tests are skipped if kernel ext4 tools are not available.
//!
//! **Behaviors compared:**
//! - Superblock: block_size, blocks_count, inodes_count, volume_name,
//!   free_blocks_count, free_inodes_count
//! - Directory listing: entry names and file types for / and /testdir
//! - Inode metadata: mode, size, links_count for files and directories
//! - File content: byte-exact read via extent mapping
//! - Extent mapping: collect_extents produces non-empty results for files

use ffs_harness::{GoldenDirEntry, GoldenReference};
use ffs_ondisk::Ext4ImageReader;
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Tool availability ───────────────────────────────────────────

fn has_command(name: &str) -> bool {
    Command::new(name)
        .arg("-V")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

fn ext4_tools_available() -> bool {
    has_command("mkfs.ext4") && has_command("debugfs") && has_command("dumpe2fs")
}

// ── Image creation ──────────────────────────────────────────────

const FILE_CONTENT: &[u8] = b"hello from FrankenFS reference test\n";

fn create_reference_image(image_path: &Path) -> PathBuf {
    // Create 8MB zero file
    let f = std::fs::File::create(image_path).expect("create image file");
    f.set_len(8 * 1024 * 1024).expect("set image length");
    drop(f);

    // Format as ext4
    let st = Command::new("mkfs.ext4")
        .args(["-L", "ffs-ref", "-b", "4096", "-q"])
        .arg(image_path)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 failed");

    // Write the content file
    let content_path = image_path.with_extension("content.tmp");
    std::fs::write(&content_path, FILE_CONTENT).expect("write content file");

    // Create /testdir
    run_debugfs_w(image_path, "mkdir /testdir");
    // Write /testdir/hello.txt
    run_debugfs_w(
        image_path,
        &format!("write {} /testdir/hello.txt", content_path.display()),
    );
    // Write /readme.txt
    run_debugfs_w(
        image_path,
        &format!("write {} /readme.txt", content_path.display()),
    );

    std::fs::remove_file(&content_path).ok();
    image_path.to_path_buf()
}

fn run_debugfs_w(image: &Path, cmd: &str) {
    let st = Command::new("debugfs")
        .args(["-w", "-R", cmd])
        .arg(image)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run debugfs");
    assert!(st.success(), "debugfs -w -R {cmd:?} failed");
}

/// Create an ext4 image without a journal (for tests that don't need journal replay).
fn create_nojournal_image(image_path: &Path) -> PathBuf {
    // Create 8MB zero file
    let f = std::fs::File::create(image_path).expect("create image file");
    f.set_len(8 * 1024 * 1024).expect("set image length");
    drop(f);

    // Format as ext4 without journal (-O ^has_journal)
    let st = Command::new("mkfs.ext4")
        .args([
            "-L",
            "ffs-nojournal",
            "-b",
            "4096",
            "-q",
            "-O",
            "^has_journal",
        ])
        .arg(image_path)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 failed");

    image_path.to_path_buf()
}

// ── Kernel tool output capture ──────────────────────────────────

struct KernelSuperblock {
    block_size: u32,
    blocks_count: u64,
    inodes_count: u32,
    volume_name: String,
    free_blocks_count: u64,
    free_inodes_count: u32,
}

fn capture_superblock(image: &Path) -> KernelSuperblock {
    let out = Command::new("dumpe2fs")
        .args(["-h"])
        .arg(image)
        .stderr(std::process::Stdio::null())
        .output()
        .expect("run dumpe2fs");
    let text = String::from_utf8_lossy(&out.stdout);

    let field = |name: &str| -> String {
        text.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_once(':'))
            .map_or_else(String::new, |(_, v)| v.trim().to_string())
    };

    KernelSuperblock {
        block_size: field("Block size").parse().expect("block_size"),
        blocks_count: field("Block count").parse().expect("blocks_count"),
        inodes_count: field("Inode count").parse().expect("inodes_count"),
        volume_name: field("Filesystem volume name"),
        free_blocks_count: field("Free blocks").parse().expect("free_blocks"),
        free_inodes_count: field("Free inodes").parse().expect("free_inodes"),
    }
}

struct KernelDirEntry {
    name: String,
    file_type: String,
}

fn capture_directory(image: &Path, dir: &str) -> Vec<KernelDirEntry> {
    let out = Command::new("debugfs")
        .args(["-R", &format!("ls -l {dir}")])
        .arg(image)
        .stderr(std::process::Stdio::null())
        .output()
        .expect("run debugfs ls");
    let text = String::from_utf8_lossy(&out.stdout);

    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("debugfs") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 8 {
            continue;
        }
        // parts[0]=inode, parts[1]=mode, ..., last=name
        let inode_str = parts[0];
        if inode_str.parse::<u32>().is_err() {
            continue;
        }
        // debugfs prints mode in octal (e.g., 40755 for dir, 100664 for file)
        let mode: u32 = match u32::from_str_radix(parts[1], 8) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let name = (*parts.last().unwrap()).to_string();
        let file_type = match mode & 0o17_0000 {
            0o4_0000 => "directory",
            0o10_0000 => "regular",
            0o2_0000 => "character",
            0o6_0000 => "block",
            0o1_0000 => "fifo",
            0o14_0000 => "socket",
            0o12_0000 => "symlink",
            _ => "unknown",
        };
        entries.push(KernelDirEntry {
            name,
            file_type: file_type.to_string(),
        });
    }
    entries
}

// ── Golden JSON helpers ─────────────────────────────────────────

fn golden_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance")
        .join("golden")
        .join("ext4_8mb_reference.json")
}

fn load_golden() -> GoldenReference {
    let text = std::fs::read_to_string(golden_path()).expect("read golden JSON");
    serde_json::from_str(&text).expect("parse golden JSON")
}

fn assert_dir_entries_match(expected: &[GoldenDirEntry], actual_names: &[(String, String)]) {
    let mut expected_set: Vec<(&str, &str)> = expected
        .iter()
        .map(|e| (e.name.as_str(), e.file_type.as_str()))
        .collect();
    expected_set.sort_unstable();

    let mut actual_set: Vec<(&str, &str)> = actual_names
        .iter()
        .map(|(n, t)| (n.as_str(), t.as_str()))
        .collect();
    actual_set.sort_unstable();

    assert_eq!(expected_set, actual_set, "directory entry mismatch");
}

fn ext4_file_type_str(mode: u16) -> &'static str {
    match mode & 0o17_0000 {
        0o10_0000 => "regular",
        0o4_0000 => "directory",
        0o2_0000 => "character",
        0o6_0000 => "block",
        0o1_0000 => "fifo",
        0o14_0000 => "socket",
        0o12_0000 => "symlink",
        _ => "unknown",
    }
}

// ── Tests ───────────────────────────────────────────────────────

/// E2E: generate a fresh ext4 image, compare kernel tools vs ffs-ondisk
/// for superblock fields.
#[test]
fn ext4_kernel_vs_ffs_superblock() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let tmp = std::env::temp_dir().join("ffs_ref_sb_test.ext4");
    create_reference_image(&tmp);

    // Kernel side
    let kernel = capture_superblock(&tmp);

    // ffs-ondisk side
    let image = std::fs::read(&tmp).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse ext4 image");

    assert_eq!(reader.sb.block_size, kernel.block_size, "block_size");
    assert_eq!(reader.sb.blocks_count, kernel.blocks_count, "blocks_count");
    assert_eq!(reader.sb.inodes_count, kernel.inodes_count, "inodes_count");
    assert_eq!(reader.sb.volume_name, kernel.volume_name, "volume_name");
    assert_eq!(
        reader.sb.free_blocks_count, kernel.free_blocks_count,
        "free_blocks_count"
    );
    assert_eq!(
        reader.sb.free_inodes_count, kernel.free_inodes_count,
        "free_inodes_count"
    );

    std::fs::remove_file(&tmp).ok();
}

/// E2E: compare directory listings between kernel tools and ffs-ondisk.
#[test]
fn ext4_kernel_vs_ffs_directory_listing() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let tmp = std::env::temp_dir().join("ffs_ref_dir_test.ext4");
    create_reference_image(&tmp);

    let image = std::fs::read(&tmp).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse ext4 image");

    // Compare root directory
    let kernel_root = capture_directory(&tmp, "/");
    let root_inode = reader
        .read_inode(&image, ffs_types::InodeNumber::ROOT)
        .expect("read root inode");
    let ffs_root = reader.read_dir(&image, &root_inode).expect("read root dir");

    let kernel_names: Vec<(String, String)> = kernel_root
        .iter()
        .map(|e| (e.name.clone(), e.file_type.clone()))
        .collect();
    let ffs_names: Vec<(String, String)> = ffs_root
        .iter()
        .map(|e| (e.name_str(), ext4_dir_entry_type_str(e).to_string()))
        .collect();

    assert_dir_entries_match_kernel(&kernel_names, &ffs_names, "/");

    // Compare /testdir
    let kernel_testdir = capture_directory(&tmp, "/testdir");
    let (_, testdir_inode) = reader
        .resolve_path(&image, "/testdir")
        .expect("resolve /testdir");
    let ffs_testdir = reader
        .read_dir(&image, &testdir_inode)
        .expect("read testdir");

    let kernel_td_names: Vec<(String, String)> = kernel_testdir
        .iter()
        .map(|e| (e.name.clone(), e.file_type.clone()))
        .collect();
    let ffs_td_names: Vec<(String, String)> = ffs_testdir
        .iter()
        .map(|e| (e.name_str(), ext4_dir_entry_type_str(e).to_string()))
        .collect();

    assert_dir_entries_match_kernel(&kernel_td_names, &ffs_td_names, "/testdir");

    std::fs::remove_file(&tmp).ok();
}

fn ext4_dir_entry_type_str(entry: &ffs_ondisk::Ext4DirEntry) -> &'static str {
    match entry.file_type {
        ffs_ondisk::Ext4FileType::RegFile => "regular",
        ffs_ondisk::Ext4FileType::Dir => "directory",
        ffs_ondisk::Ext4FileType::Chrdev => "character",
        ffs_ondisk::Ext4FileType::Blkdev => "block",
        ffs_ondisk::Ext4FileType::Fifo => "fifo",
        ffs_ondisk::Ext4FileType::Sock => "socket",
        ffs_ondisk::Ext4FileType::Symlink => "symlink",
        ffs_ondisk::Ext4FileType::Unknown => "unknown",
    }
}

fn assert_dir_entries_match_kernel(
    kernel: &[(String, String)],
    ffs: &[(String, String)],
    path: &str,
) {
    let mut k_sorted: Vec<_> = kernel
        .iter()
        .map(|(n, t)| (n.as_str(), t.as_str()))
        .collect();
    k_sorted.sort_unstable();
    let mut f_sorted: Vec<_> = ffs.iter().map(|(n, t)| (n.as_str(), t.as_str())).collect();
    f_sorted.sort_unstable();
    assert_eq!(
        k_sorted, f_sorted,
        "directory {path}: kernel vs ffs-ondisk entry mismatch"
    );
}

/// E2E: read file content via ffs-ondisk and compare against known bytes.
#[test]
fn ext4_kernel_vs_ffs_file_content() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let tmp = std::env::temp_dir().join("ffs_ref_file_test.ext4");
    create_reference_image(&tmp);

    let image = std::fs::read(&tmp).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse ext4 image");

    for path in ["/testdir/hello.txt", "/readme.txt"] {
        let (_, inode) = reader
            .resolve_path(&image, path)
            .unwrap_or_else(|e| panic!("resolve {path}: {e}"));

        // Read file content
        #[allow(clippy::cast_possible_truncation)]
        let mut buf = vec![0u8; inode.size as usize];
        let bytes_read = reader
            .read_inode_data(&image, &inode, 0, &mut buf)
            .unwrap_or_else(|e| panic!("read {path}: {e}"));

        assert_eq!(bytes_read, FILE_CONTENT.len(), "{path}: size mismatch");
        assert_eq!(&buf[..bytes_read], FILE_CONTENT, "{path}: content mismatch");
    }

    std::fs::remove_file(&tmp).ok();
}

/// E2E: verify inode metadata (mode, size, links_count) for known files.
#[test]
fn ext4_kernel_vs_ffs_inode_metadata() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let tmp = std::env::temp_dir().join("ffs_ref_inode_test.ext4");
    create_reference_image(&tmp);

    let image = std::fs::read(&tmp).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse ext4 image");

    // Root directory: should be a directory with at least 3 links
    let root = reader
        .read_inode(&image, ffs_types::InodeNumber::ROOT)
        .expect("read root inode");
    assert_eq!(
        ext4_file_type_str(root.mode),
        "directory",
        "root should be directory"
    );
    assert!(
        root.links_count >= 3,
        "root links_count should be >= 3 (., .., lost+found, testdir)"
    );

    // /testdir: directory with links >= 2
    let (_, testdir) = reader
        .resolve_path(&image, "/testdir")
        .expect("resolve /testdir");
    assert_eq!(
        ext4_file_type_str(testdir.mode),
        "directory",
        "/testdir should be directory"
    );
    assert!(testdir.links_count >= 2, "/testdir links >= 2");

    // /testdir/hello.txt: regular file
    let (_, hello) = reader
        .resolve_path(&image, "/testdir/hello.txt")
        .expect("resolve /testdir/hello.txt");
    assert_eq!(
        ext4_file_type_str(hello.mode),
        "regular",
        "hello.txt should be regular"
    );
    #[allow(clippy::cast_possible_truncation)]
    let expected_size = FILE_CONTENT.len() as u64;
    assert_eq!(hello.size, expected_size, "hello.txt size");
    assert_eq!(hello.links_count, 1, "hello.txt links_count");

    // /readme.txt: regular file
    let (_, readme) = reader
        .resolve_path(&image, "/readme.txt")
        .expect("resolve /readme.txt");
    assert_eq!(
        ext4_file_type_str(readme.mode),
        "regular",
        "readme.txt should be regular"
    );
    assert_eq!(readme.size, expected_size, "readme.txt size");

    std::fs::remove_file(&tmp).ok();
}

/// E2E: verify extent mapping produces valid results for files with content.
#[test]
fn ext4_kernel_vs_ffs_extent_mapping() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let tmp = std::env::temp_dir().join("ffs_ref_extent_test.ext4");
    create_reference_image(&tmp);

    let image = std::fs::read(&tmp).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse ext4 image");

    // hello.txt has content, so it should have at least one extent
    let (_, hello) = reader
        .resolve_path(&image, "/testdir/hello.txt")
        .expect("resolve hello.txt");
    let extents = reader
        .collect_extents(&image, &hello)
        .expect("collect extents");
    assert!(
        !extents.is_empty(),
        "hello.txt should have at least one extent"
    );
    assert_eq!(
        extents[0].logical_block, 0,
        "first extent starts at block 0"
    );
    assert!(
        extents[0].raw_len > 0,
        "extent should cover at least one block"
    );

    std::fs::remove_file(&tmp).ok();
}

/// Verify the checked-in golden JSON parses and is internally consistent.
#[test]
fn golden_json_parses_and_is_consistent() {
    let golden = load_golden();
    assert_eq!(golden.version, 1);
    assert_eq!(golden.image_params.block_size, golden.superblock.block_size);
    assert_eq!(
        golden.image_params.volume_name,
        golden.superblock.volume_name
    );
    assert!(golden.superblock.blocks_count > 0);
    assert!(golden.superblock.inodes_count > 0);
    assert!(!golden.directories.is_empty());
    assert!(!golden.files.is_empty());

    // Root directory should have standard entries
    let root = golden
        .directories
        .iter()
        .find(|d| d.path == "/")
        .expect("golden should have root directory");
    assert!(root.entries.iter().any(|e| e.name == "."));
    assert!(root.entries.iter().any(|e| e.name == ".."));
}

/// E2E: compare ffs-ondisk parsing against the checked-in golden JSON.
#[test]
fn ffs_ondisk_matches_golden_json() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let golden = load_golden();

    // Generate a fresh image with the same parameters
    let tmp = std::env::temp_dir().join("ffs_ref_golden_test.ext4");
    create_reference_image(&tmp);

    let image = std::fs::read(&tmp).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse ext4 image");

    // Superblock
    assert_eq!(reader.sb.block_size, golden.superblock.block_size);
    assert_eq!(reader.sb.blocks_count, golden.superblock.blocks_count);
    assert_eq!(reader.sb.inodes_count, golden.superblock.inodes_count);
    assert_eq!(reader.sb.volume_name, golden.superblock.volume_name);

    // Directories
    for gdir in &golden.directories {
        let (_, inode) = reader
            .resolve_path(&image, &gdir.path)
            .unwrap_or_else(|e| panic!("resolve {}: {e}", gdir.path));
        let entries = reader
            .read_dir(&image, &inode)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", gdir.path));
        let ffs_names: Vec<(String, String)> = entries
            .iter()
            .map(|e| (e.name_str(), ext4_dir_entry_type_str(e).to_string()))
            .collect();
        assert_dir_entries_match(&gdir.entries, &ffs_names);
        assert_eq!(
            ffs_names.len(),
            gdir.entries.len(),
            "{}: entry count mismatch",
            gdir.path
        );
    }

    // Files
    for gfile in &golden.files {
        let (_, inode) = reader
            .resolve_path(&image, &gfile.path)
            .unwrap_or_else(|e| panic!("resolve {}: {e}", gfile.path));
        assert_eq!(inode.size, gfile.size, "{}: size mismatch", gfile.path);

        #[allow(clippy::cast_possible_truncation)]
        let mut buf = vec![0u8; inode.size as usize];
        let n = reader
            .read_inode_data(&image, &inode, 0, &mut buf)
            .unwrap_or_else(|e| panic!("read {}: {e}", gfile.path));
        assert_eq!(
            &buf[..n],
            &gfile.content,
            "{}: content mismatch",
            gfile.path
        );
    }

    std::fs::remove_file(&tmp).ok();
}

/// E2E: verify OpenFs bitmap-based free space counting matches kernel tools.
///
/// This test exercises the bitmap reading API (bd-1xe.2) by:
/// 1. Creating an ext4 image with mkfs.ext4 (no journal to avoid replay issues)
/// 2. Using OpenFs::free_space_summary() to count free blocks/inodes from bitmaps
/// 3. Comparing against dumpe2fs output
/// 4. Verifying that bitmap counts match group descriptor cached values
#[test]
fn ext4_bitmap_free_space_matches_kernel() {
    use asupersync::Cx;
    use ffs_core::OpenFs;

    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let tmp = std::env::temp_dir().join("ffs_bitmap_free_test.ext4");
    // Create image without journal to avoid journal replay issues
    create_nojournal_image(&tmp);

    // Get kernel view via dumpe2fs
    let kernel = capture_superblock(&tmp);

    // Get FrankenFS view via OpenFs bitmap reading
    let cx = Cx::for_request();
    let open_fs = OpenFs::open(&cx, &tmp).expect("open ext4 image");
    let summary = open_fs
        .free_space_summary(&cx)
        .expect("compute free space summary");

    // Compare bitmap-derived counts against kernel tools
    assert_eq!(
        summary.free_blocks_total, kernel.free_blocks_count,
        "bitmap free_blocks_total should match dumpe2fs"
    );
    assert_eq!(
        summary.free_inodes_total,
        u64::from(kernel.free_inodes_count),
        "bitmap free_inodes_total should match dumpe2fs"
    );

    // Verify bitmap counts match group descriptor cached values (no corruption)
    assert!(
        !summary.blocks_mismatch,
        "bitmap block count should match group descriptors: bitmap={}, gd={}",
        summary.free_blocks_total, summary.gd_free_blocks_total
    );
    assert!(
        !summary.inodes_mismatch,
        "bitmap inode count should match group descriptors: bitmap={}, gd={}",
        summary.free_inodes_total, summary.gd_free_inodes_total
    );

    std::fs::remove_file(&tmp).ok();
}
