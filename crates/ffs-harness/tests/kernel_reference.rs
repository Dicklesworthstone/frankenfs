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
//! - Extent mapping: `collect_extents` matches `debugfs blocks`, including a
//!   deterministic fragmented two-extent file

use asupersync::Cx;
use ffs_core::{OpenFs, OpenOptions};
use ffs_harness::{GoldenDirEntry, GoldenReference};
use ffs_ondisk::{
    Ext4ImageReader, dx_hash, parse_dx_root, parse_ibody_xattrs, parse_xattr_block,
    stamp_dir_block_checksum, verify_dir_block_checksum, verify_inode_checksum,
};
use ffs_types::{
    BlockNumber, EXT4_INLINE_DATA_FL, EXT4_XATTR_INDEX_POSIX_ACL_ACCESS,
    EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT, EXT4_XATTR_INDEX_SECURITY, EXT4_XATTR_INDEX_SYSTEM,
    EXT4_XATTR_INDEX_USER, InodeNumber,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

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
    has_command("mkfs.ext4")
        && has_command("debugfs")
        && has_command("dumpe2fs")
        && has_command("e2fsck")
}

// ── Image creation ──────────────────────────────────────────────

const FILE_CONTENT: &[u8] = b"hello from FrankenFS reference test\n";
const LARGE_FILE_CONTENT: &[u8] = b"hello from FrankenFS 64mb geometry variant\n";
const DIR_INDEX_FILE_CONTENT: &[u8] = b"hello from FrankenFS dir_index variant\n";
const HTREE_GOLDEN_FILE_CONTENT: &[u8] = b"x";
const DIR_INDEX_HASH_SEED: &str = "11111111-2222-3333-4444-555555555555";
const INLINE_XATTR_USER_VALUE: &str = "image/png";
const INLINE_XATTR_SECURITY_VALUE: &str = "system_u:object_r:tmp_t:s0";
const EXTERNAL_XATTR_VALUE_LEN: usize = 512;
const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;
const ACL_USER_OBJ_TAG: u16 = 0x0001;
const ACL_GROUP_OBJ_TAG: u16 = 0x0004;
const ACL_OTHER_TAG: u16 = 0x0020;
const ACL_UNDEFINED_ID: u32 = u32::MAX;
const INLINE_DATA_CONTINUATION_PATH: &str = "/inline76.txt";
const LARGE_ISIZE_HIGH_PATH: &str = "/huge_sparse_i_size_high.bin";
const LARGE_ISIZE_HIGH_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const LARGE_ISIZE_HIGH_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const LARGE_ISIZE_HIGH_SEED_BYTES: usize = 4096;
const HTREE_GOLDEN_FILE_COUNT: usize = 200;
const SPARSE_SUPER_MEDIUM_BLOCKS: usize = 1;
const SPARSE_SUPER_LARGE_BLOCKS: usize = 6;
// Keep this large enough that e2fsck -D reliably promotes /htree into a real
// hash-indexed directory across supported e2fsprogs versions.
const DIR_INDEX_FILE_COUNT: usize = 256;

fn trace_ext4_tools() -> bool {
    std::env::var_os("FFS_TRACE_EXT4_TOOLS").is_some()
}

fn create_reference_image(image_path: &Path) -> PathBuf {
    // Create 8MB zero file
    let f = std::fs::File::create(image_path).expect("create image file");
    f.set_len(8 * 1024 * 1024).expect("set image length");
    drop(f);

    // Format as ext4
    if trace_ext4_tools() {
        eprintln!(
            "mkfs.ext4 params: -L ffs-ref -b 4096 -q {}",
            image_path.display()
        );
    }
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
    if trace_ext4_tools() {
        eprintln!("debugfs params: -w -R {cmd:?} {}", image.display());
    }
    let st = Command::new("debugfs")
        .args(["-w", "-R", cmd])
        .arg(image)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run debugfs");
    assert!(st.success(), "debugfs -w -R {cmd:?} failed");
}

fn run_e2fsck_dir_index(image: &Path) {
    if trace_ext4_tools() {
        eprintln!("e2fsck params: -fyD {}", image.display());
    }
    let st = Command::new("e2fsck")
        .args(["-fyD"])
        .arg(image)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run e2fsck");

    let code = st.code().unwrap_or(-1);
    assert!(
        matches!(code, 0 | 1),
        "e2fsck -fyD failed with exit code {code}"
    );
}

/// Create a larger ext4 image variant (64 MiB, 4 KiB blocks) for golden tests.
fn create_large_reference_image(image_path: &Path) -> PathBuf {
    let f = std::fs::File::create(image_path).expect("create image file");
    f.set_len(64 * 1024 * 1024).expect("set image length");
    drop(f);

    if trace_ext4_tools() {
        eprintln!(
            "mkfs.ext4 params: -L ffs-ref-64 -b 4096 -q {}",
            image_path.display()
        );
    }
    let st = Command::new("mkfs.ext4")
        .args(["-L", "ffs-ref-64", "-b", "4096", "-q"])
        .arg(image_path)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 failed");

    let content_path = image_path.with_extension("large.content.tmp");
    std::fs::write(&content_path, LARGE_FILE_CONTENT).expect("write content file");

    run_debugfs_w(image_path, "mkdir /deep");
    run_debugfs_w(image_path, "mkdir /deep/nested");
    run_debugfs_w(
        image_path,
        &format!("write {} /deep/nested/data.txt", content_path.display()),
    );
    run_debugfs_w(
        image_path,
        &format!("write {} /readme64.txt", content_path.display()),
    );

    std::fs::remove_file(&content_path).ok();
    image_path.to_path_buf()
}

/// Create a dir_index-focused ext4 image variant with many directory entries.
fn create_dir_index_reference_image(image_path: &Path) -> PathBuf {
    let f = std::fs::File::create(image_path).expect("create image file");
    f.set_len(64 * 1024 * 1024).expect("set image length");
    drop(f);

    if trace_ext4_tools() {
        eprintln!(
            "mkfs.ext4 params: -L ffs-ref-dx -b 4096 -q -O dir_index {}",
            image_path.display()
        );
    }
    let st = Command::new("mkfs.ext4")
        .args(["-L", "ffs-ref-dx", "-b", "4096", "-q", "-O", "dir_index"])
        .arg(image_path)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 -O dir_index failed");
    run_debugfs_w(
        image_path,
        &format!("set_super_value hash_seed {DIR_INDEX_HASH_SEED}"),
    );

    run_debugfs_w(image_path, "mkdir /htree");

    let content_path = image_path.with_extension("dir_index.content.tmp");
    std::fs::write(&content_path, DIR_INDEX_FILE_CONTENT).expect("write content file");

    for idx in 0..DIR_INDEX_FILE_COUNT {
        let cmd = format!("write {} /htree/file_{idx:03}.txt", content_path.display());
        run_debugfs_w(image_path, &cmd);
    }
    run_debugfs_w(
        image_path,
        &format!("write {} /readme-dx.txt", content_path.display()),
    );
    // debugfs population alone does not guarantee that /htree materializes an
    // on-disk DX root. e2fsck -D rebuilds the directory index so the reference
    // image actually exercises ext4's hash-tree lookup contract.
    run_e2fsck_dir_index(image_path);

    std::fs::remove_file(&content_path).ok();
    image_path.to_path_buf()
}

/// Create the committed 64 MiB sparse_super golden image variant.
fn create_sparse_super_golden_image(image_path: &Path) -> PathBuf {
    let f = std::fs::File::create(image_path).expect("create image file");
    f.set_len(64 * 1024 * 1024).expect("set image length");
    drop(f);

    if trace_ext4_tools() {
        eprintln!(
            "mkfs.ext4 params: -L ffs-64mb -b 4096 -q -O sparse_super {}",
            image_path.display()
        );
    }
    let st = Command::new("mkfs.ext4")
        .args(["-L", "ffs-64mb", "-b", "4096", "-q", "-O", "sparse_super"])
        .arg(image_path)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 -O sparse_super failed");

    let small_path = image_path.with_extension("sparse.small.tmp");
    let empty_path = image_path.with_extension("sparse.empty.tmp");
    let medium_path = image_path.with_extension("sparse.medium.tmp");
    let large_path = image_path.with_extension("sparse.large.tmp");
    std::fs::write(&small_path, FILE_CONTENT).expect("write small content file");
    std::fs::write(&empty_path, []).expect("write empty content file");
    std::fs::write(&medium_path, vec![b'M'; SPARSE_SUPER_MEDIUM_BLOCKS * 4096])
        .expect("write medium content file");
    std::fs::write(&large_path, vec![b'L'; SPARSE_SUPER_LARGE_BLOCKS * 4096])
        .expect("write large content file");

    run_debugfs_w(image_path, "mkdir /a");
    run_debugfs_w(image_path, "mkdir /a/b");
    run_debugfs_w(image_path, "mkdir /a/b/c");
    run_debugfs_w(
        image_path,
        &format!("write {} /a/small.txt", small_path.display()),
    );
    run_debugfs_w(
        image_path,
        &format!("write {} /empty.dat", empty_path.display()),
    );
    run_debugfs_w(image_path, "symlink /link_to_small /a/small.txt");
    run_debugfs_w(
        image_path,
        &format!("write {} /a/b/medium.bin", medium_path.display()),
    );
    run_debugfs_w(
        image_path,
        &format!("write {} /a/b/c/large.bin", large_path.display()),
    );

    std::fs::remove_file(&small_path).ok();
    std::fs::remove_file(&empty_path).ok();
    std::fs::remove_file(&medium_path).ok();
    std::fs::remove_file(&large_path).ok();
    image_path.to_path_buf()
}

/// Create the committed 8 MiB htree/dir_index golden image variant.
fn create_htree_dirindex_golden_image(image_path: &Path) -> PathBuf {
    let f = std::fs::File::create(image_path).expect("create image file");
    f.set_len(8 * 1024 * 1024).expect("set image length");
    drop(f);

    if trace_ext4_tools() {
        eprintln!(
            "mkfs.ext4 params: -L ffs-htree -b 4096 -q -O dir_index {}",
            image_path.display()
        );
    }
    let st = Command::new("mkfs.ext4")
        .args(["-L", "ffs-htree", "-b", "4096", "-q", "-O", "dir_index"])
        .arg(image_path)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 -O dir_index failed");
    run_debugfs_w(
        image_path,
        &format!("set_super_value hash_seed {DIR_INDEX_HASH_SEED}"),
    );

    run_debugfs_w(image_path, "mkdir /bigdir");

    let content_path = image_path.with_extension("htree.content.tmp");
    std::fs::write(&content_path, HTREE_GOLDEN_FILE_CONTENT).expect("write htree content file");

    for idx in 0..HTREE_GOLDEN_FILE_COUNT {
        let cmd = format!("write {} /bigdir/file_{idx:03}.txt", content_path.display());
        run_debugfs_w(image_path, &cmd);
    }
    run_debugfs_w(
        image_path,
        &format!("write {} /marker.txt", content_path.display()),
    );
    run_e2fsck_dir_index(image_path);

    std::fs::remove_file(&content_path).ok();
    image_path.to_path_buf()
}

/// Create an ext4 image without a journal (for tests that don't need journal replay).
fn create_nojournal_image(image_path: &Path) -> PathBuf {
    // Create 8MB zero file
    let f = std::fs::File::create(image_path).expect("create image file");
    f.set_len(8 * 1024 * 1024).expect("set image length");
    drop(f);

    // Format as ext4 without journal (-O ^has_journal)
    if trace_ext4_tools() {
        eprintln!(
            "mkfs.ext4 params: -L ffs-nojournal -b 4096 -q -O ^has_journal {}",
            image_path.display()
        );
    }
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

fn create_fragmented_extent_reference_image(image_path: &Path) -> PathBuf {
    let f = std::fs::File::create(image_path).expect("create image file");
    f.set_len(32 * 1024 * 1024).expect("set image length");
    drop(f);

    if trace_ext4_tools() {
        eprintln!(
            "mkfs.ext4 params: -L ffs-extents -b 4096 -q {}",
            image_path.display()
        );
    }
    let st = Command::new("mkfs.ext4")
        .args(["-L", "ffs-extents", "-b", "4096", "-q"])
        .arg(image_path)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 failed");

    let first_path = image_path.with_extension("extent.first.tmp");
    let second_path = image_path.with_extension("extent.second.tmp");
    let target_path = image_path.with_extension("extent.target.tmp");
    std::fs::write(&first_path, vec![b'A'; 4 * 4096]).expect("write first extent payload");
    std::fs::write(&second_path, vec![b'B'; 4 * 4096]).expect("write second extent payload");
    std::fs::write(&target_path, vec![b'C'; (6 * 4096) + 123])
        .expect("write fragmented target payload");

    run_debugfs_w(image_path, "mkdir /frag");
    run_debugfs_w(
        image_path,
        &format!("write {} /frag/a.bin", first_path.display()),
    );
    run_debugfs_w(
        image_path,
        &format!("write {} /frag/b.bin", second_path.display()),
    );
    run_debugfs_w(image_path, "rm /frag/a.bin");
    run_debugfs_w(
        image_path,
        &format!("write {} /frag/target.bin", target_path.display()),
    );

    std::fs::remove_file(&first_path).ok();
    std::fs::remove_file(&second_path).ok();
    std::fs::remove_file(&target_path).ok();
    image_path.to_path_buf()
}

fn inline_data_continuation_payload() -> Vec<u8> {
    let mut payload = vec![b'A'; 60];
    payload.extend(std::iter::repeat_n(b'B', 16));
    payload
}

fn create_inline_data_reference_image(image_path: &Path) -> PathBuf {
    let f = std::fs::File::create(image_path).expect("create image file");
    f.set_len(8 * 1024 * 1024).expect("set image length");
    drop(f);

    if trace_ext4_tools() {
        eprintln!(
            "mkfs.ext4 params: -L ffs-inline-ref -b 4096 -q -O inline_data {}",
            image_path.display()
        );
    }
    let st = Command::new("mkfs.ext4")
        .args([
            "-L",
            "ffs-inline-ref",
            "-b",
            "4096",
            "-q",
            "-O",
            "inline_data",
        ])
        .arg(image_path)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 -O inline_data failed");

    let payload_path = image_path.with_extension("inline_data.content.tmp");
    std::fs::write(&payload_path, inline_data_continuation_payload())
        .expect("write inline-data continuation payload");
    run_debugfs_w(
        image_path,
        &format!(
            "write {} {INLINE_DATA_CONTINUATION_PATH}",
            payload_path.display()
        ),
    );
    std::fs::remove_file(&payload_path).ok();
    image_path.to_path_buf()
}

fn create_xattr_base_image(image_path: &Path) -> PathBuf {
    let f = std::fs::File::create(image_path).expect("create image file");
    f.set_len(8 * 1024 * 1024).expect("set image length");
    drop(f);

    if trace_ext4_tools() {
        eprintln!(
            "mkfs.ext4 params: -L ffs-xattr-ref -b 4096 -q {}",
            image_path.display()
        );
    }
    let st = Command::new("mkfs.ext4")
        .args(["-L", "ffs-xattr-ref", "-b", "4096", "-q"])
        .arg(image_path)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 failed");

    let payload_path = image_path.with_extension("xattr.content.tmp");
    std::fs::write(&payload_path, FILE_CONTENT).expect("write xattr content file");

    run_debugfs_w(image_path, "mkdir /xattrs");
    run_debugfs_w(
        image_path,
        &format!("write {} /xattrs/inline.txt", payload_path.display()),
    );
    run_debugfs_w(
        image_path,
        &format!("write {} /xattrs/external.txt", payload_path.display()),
    );
    run_debugfs_w(
        image_path,
        &format!("write {} /xattrs/acl_access.txt", payload_path.display()),
    );
    run_debugfs_w(image_path, "mkdir /xattrs/acl_dir");
    std::fs::remove_file(&payload_path).ok();
    image_path.to_path_buf()
}

fn build_posix_acl_xattr(entries: &[(u16, u16)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + (entries.len() * 8));
    out.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
    for (tag, perm) in entries {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&perm.to_le_bytes());
        out.extend_from_slice(&ACL_UNDEFINED_ID.to_le_bytes());
    }
    out
}

fn apply_xattr_reference_mutations(image_path: &Path) {
    run_debugfs_w(
        image_path,
        &format!("ea_set /xattrs/inline.txt user.mime {INLINE_XATTR_USER_VALUE}"),
    );
    run_debugfs_w(
        image_path,
        &format!("ea_set /xattrs/inline.txt security.selinux {INLINE_XATTR_SECURITY_VALUE}"),
    );

    let external_value = "X".repeat(EXTERNAL_XATTR_VALUE_LEN);
    run_debugfs_w(
        image_path,
        &format!("ea_set /xattrs/external.txt user.big {external_value}"),
    );

    let acl_access_path = image_path.with_extension("acl_access.bin");
    let acl_default_path = image_path.with_extension("acl_default.bin");
    std::fs::write(
        &acl_access_path,
        build_posix_acl_xattr(&[
            (ACL_USER_OBJ_TAG, 0o6),
            (ACL_GROUP_OBJ_TAG, 0o4),
            (ACL_OTHER_TAG, 0),
        ]),
    )
    .expect("write ACL access blob");
    std::fs::write(
        &acl_default_path,
        build_posix_acl_xattr(&[
            (ACL_USER_OBJ_TAG, 0o7),
            (ACL_GROUP_OBJ_TAG, 0o5),
            (ACL_OTHER_TAG, 0o1),
        ]),
    )
    .expect("write ACL default blob");
    run_debugfs_w(
        image_path,
        &format!(
            "ea_set -f {} /xattrs/acl_access.txt system.posix_acl_access",
            acl_access_path.display()
        ),
    );
    run_debugfs_w(
        image_path,
        &format!(
            "ea_set -f {} /xattrs/acl_dir system.posix_acl_default",
            acl_default_path.display()
        ),
    );
    std::fs::remove_file(&acl_access_path).ok();
    std::fs::remove_file(&acl_default_path).ok();
}

fn canonicalize_xattr_block_for_writer_reference(block: &[u8]) -> Vec<u8> {
    let mut canonical = block.to_vec();
    if canonical.len() >= 20 {
        // `ffs_xattr::set_xattr` does not know the checksum seed or physical
        // block number, so h_checksum cannot be reproduced at this layer.
        canonical[16..20].fill(0);
    }
    canonical
}

fn create_xattr_reference_image(image_path: &Path) -> PathBuf {
    create_xattr_base_image(image_path);
    apply_xattr_reference_mutations(image_path);
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct KernelXattr {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelExtentMapping {
    logical_block: u32,
    physical_start: u64,
    len: u16,
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

fn capture_block_map(image: &Path, path: &str) -> Vec<u64> {
    let out = Command::new("debugfs")
        .args(["-R", &format!("blocks {path}")])
        .arg(image)
        .stderr(std::process::Stdio::null())
        .output()
        .expect("run debugfs blocks");
    assert!(out.status.success(), "debugfs blocks failed for {path}");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .rev()
        .find(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with("debugfs")
        })
        .unwrap_or_else(|| panic!("debugfs blocks returned no block list for {path}"));
    let blocks: Vec<_> = line
        .split_whitespace()
        .map(|token| {
            token
                .parse::<u64>()
                .unwrap_or_else(|err| panic!("parse debugfs block {token} for {path}: {err}"))
        })
        .collect();
    assert!(!blocks.is_empty(), "expected at least one block for {path}");
    blocks
}

fn collapse_block_map_to_extents(blocks: &[u64]) -> Vec<KernelExtentMapping> {
    assert!(!blocks.is_empty(), "block map must not be empty");

    let mut extents = Vec::new();
    let mut run_start = 0_usize;
    for idx in 1..=blocks.len() {
        let continues = idx < blocks.len() && blocks[idx] == blocks[idx - 1] + 1;
        if continues {
            continue;
        }

        extents.push(KernelExtentMapping {
            logical_block: u32::try_from(run_start).expect("logical block fits u32"),
            physical_start: blocks[run_start],
            len: u16::try_from(idx - run_start).expect("extent length fits u16"),
        });
        run_start = idx;
    }

    extents
}

fn normalize_ffs_extent_map(extents: &[ffs_ondisk::Ext4Extent]) -> Vec<KernelExtentMapping> {
    extents
        .iter()
        .map(|extent| KernelExtentMapping {
            logical_block: extent.logical_block,
            physical_start: extent.physical_start,
            len: extent.actual_len(),
        })
        .collect()
}

fn expand_ffs_extent_blocks(extents: &[ffs_ondisk::Ext4Extent]) -> Vec<u64> {
    let mut blocks = Vec::new();
    for extent in extents {
        for delta in 0..u64::from(extent.actual_len()) {
            blocks.push(extent.physical_start + delta);
        }
    }
    blocks
}

fn parse_kernel_xattr_name(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with("debugfs") || line == "Extended attributes:" {
        return None;
    }

    let (name, _) = line.split_once(" (")?;
    Some(name.to_string())
}

fn capture_xattrs(image: &Path, path: &str) -> Vec<KernelXattr> {
    let out = Command::new("debugfs")
        .args(["-R", &format!("ea_list {path}")])
        .arg(image)
        .stderr(std::process::Stdio::null())
        .output()
        .expect("run debugfs ea_list");
    assert!(out.status.success(), "debugfs ea_list failed for {path}");

    let mut attrs: Vec<_> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(parse_kernel_xattr_name)
        .map(|name| KernelXattr {
            value: capture_xattr_value(image, path, &name),
            name,
        })
        .collect();
    attrs.sort_unstable();
    attrs
}

fn capture_xattr_value(image: &Path, path: &str, name: &str) -> String {
    if is_posix_acl_xattr(name) {
        return capture_stat_xattr_value(image, path, name);
    }

    let out = Command::new("debugfs")
        .args(["-R", &format!("ea_get {path} {name}")])
        .arg(image)
        .stderr(std::process::Stdio::null())
        .output()
        .expect("run debugfs ea_get");
    assert!(
        out.status.success(),
        "debugfs ea_get failed for {path} {name}"
    );

    let attr = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with("debugfs") {
                return None;
            }
            let (lhs, rhs) = line.split_once(" = ")?;
            let (attr_name, _) = lhs.split_once(" (")?;
            Some(KernelXattr {
                name: attr_name.to_string(),
                value: rhs.trim().trim_matches('"').to_string(),
            })
        })
        .unwrap_or_else(|| panic!("debugfs ea_get returned no xattr for {path} {name}"));
    assert_eq!(attr.name, name, "debugfs ea_get returned wrong xattr");
    attr.value
}

fn capture_xattr_raw_value(image: &Path, path: &str, name: &str) -> Vec<u8> {
    if is_posix_acl_xattr(name) {
        let out = Command::new("debugfs")
            .args(["-R", &format!("stat {path}")])
            .arg(image)
            .stderr(std::process::Stdio::null())
            .output()
            .expect("run debugfs stat for ACL xattr");
        assert!(out.status.success(), "debugfs stat failed for {path}");
        return parse_debugfs_xattr_hex(&out.stdout, path, name);
    }

    let out = Command::new("debugfs")
        .args(["-R", &format!("ea_get -x {path} {name}")])
        .arg(image)
        .stderr(std::process::Stdio::null())
        .output()
        .expect("run debugfs ea_get");
    assert!(
        out.status.success(),
        "debugfs ea_get failed for {path} {name}"
    );
    parse_debugfs_xattr_hex(&out.stdout, path, name)
}

fn capture_stat_xattr_value(image: &Path, path: &str, name: &str) -> String {
    let out = Command::new("debugfs")
        .args(["-R", &format!("stat {path}")])
        .arg(image)
        .stderr(std::process::Stdio::null())
        .output()
        .expect("run debugfs stat for xattr");
    assert!(out.status.success(), "debugfs stat failed for {path}");

    let attr = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with("debugfs") {
                return None;
            }
            let (lhs, rhs) = line.split_once(" = ")?;
            let (attr_name, _) = lhs.split_once(" (")?;
            Some(KernelXattr {
                name: attr_name.to_string(),
                value: rhs.trim().trim_matches('"').to_string(),
            })
        })
        .filter(|attr| attr.name == name)
        .unwrap_or_else(|| panic!("debugfs stat returned no xattr for {path} {name}"));
    attr.value
}

fn parse_debugfs_xattr_hex(stdout: &[u8], path: &str, name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut collecting = false;

    for line in String::from_utf8_lossy(stdout).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("debugfs") {
            continue;
        }

        let fragment = if let Some((prefix, suffix)) = line.split_once(" = ") {
            if !prefix.starts_with(name) {
                continue;
            }
            collecting = true;
            suffix
        } else if collecting {
            line
        } else {
            continue;
        };

        for token in fragment.split_whitespace() {
            if token.len() != 2 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                continue;
            }
            bytes.push(
                u8::from_str_radix(token, 16)
                    .unwrap_or_else(|err| panic!("decode debugfs hex token {token}: {err}")),
            );
        }
    }

    assert!(
        collecting,
        "debugfs ea_get -x produced no xattr payload for {path} {name}"
    );
    bytes
}

fn normalize_ffs_xattrs(xattrs: Vec<ffs_ondisk::Ext4Xattr>) -> Vec<KernelXattr> {
    let mut normalized: Vec<_> = xattrs
        .into_iter()
        .map(|xattr| KernelXattr {
            name: xattr.full_name(),
            value: render_reference_xattr_value(&xattr),
        })
        .collect();
    normalized.sort_unstable();
    normalized
}

fn render_reference_xattr_value(xattr: &ffs_ondisk::Ext4Xattr) -> String {
    if xattr.name_index == EXT4_XATTR_INDEX_POSIX_ACL_ACCESS
        || xattr.name_index == EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT
    {
        return xattr
            .value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
    }

    String::from_utf8(xattr.value.clone())
        .unwrap_or_else(|err| panic!("xattr value should be utf-8 for test fixture: {err}"))
}

fn xattr_writer_access() -> ffs_xattr::XattrWriteAccess {
    ffs_xattr::XattrWriteAccess {
        is_owner: true,
        has_cap_fowner: true,
        has_cap_sys_admin: true,
    }
}

fn is_posix_acl_xattr(name: &str) -> bool {
    matches!(name, "system.posix_acl_access" | "system.posix_acl_default")
}

fn unique_temp_ext4_path(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("ffs_{tag}_{}_{}.ext4", std::process::id(), nanos))
}

fn create_large_isize_high_reference_image(image_path: &Path) -> PathBuf {
    let f = std::fs::File::create(image_path).expect("create image file");
    f.set_len(LARGE_ISIZE_HIGH_IMAGE_BYTES)
        .expect("set sparse image length");
    drop(f);

    if trace_ext4_tools() {
        eprintln!(
            "mkfs.ext4 params: -L ffs-isizehi -b 4096 -q -O ^has_journal {}",
            image_path.display()
        );
    }
    let st = Command::new("mkfs.ext4")
        .args([
            "-L",
            "ffs-isizehi",
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

    let seed_path = image_path.with_extension("i_size_high.seed.tmp");
    std::fs::write(&seed_path, vec![b'H'; LARGE_ISIZE_HIGH_SEED_BYTES])
        .expect("write i_size_high seed");
    run_debugfs_w(
        image_path,
        &format!("write {} {LARGE_ISIZE_HIGH_PATH}", seed_path.display()),
    );
    run_debugfs_w(
        image_path,
        &format!("sif {LARGE_ISIZE_HIGH_PATH} size {LARGE_ISIZE_HIGH_BYTES}"),
    );
    std::fs::remove_file(&seed_path).ok();

    image_path.to_path_buf()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DebugfsInodeStat {
    inode_number: u64,
    size: u64,
}

fn parse_debugfs_u64_field(text: &str, field: &str) -> Option<u64> {
    let needle = format!("{field}:");
    for line in text.lines() {
        if let Some((_, rest)) = line.split_once(&needle) {
            let token = rest.split_whitespace().next()?;
            return token.parse().ok();
        }
    }
    None
}

fn capture_debugfs_inode_stat(image: &Path, path: &str) -> DebugfsInodeStat {
    let out = Command::new("debugfs")
        .args(["-R", &format!("stat {path}")])
        .arg(image)
        .stderr(std::process::Stdio::null())
        .output()
        .expect("run debugfs stat");
    assert!(out.status.success(), "debugfs stat failed for {path}");

    let text = String::from_utf8_lossy(&out.stdout);
    DebugfsInodeStat {
        inode_number: parse_debugfs_u64_field(&text, "Inode")
            .expect("debugfs stat missing numeric Inode field"),
        size: parse_debugfs_u64_field(&text, "Size")
            .expect("debugfs stat missing numeric Size field"),
    }
}

fn raw_inode_size_words(image: &[u8], reader: &Ext4ImageReader, ino: InodeNumber) -> (u32, u32) {
    let (group, _index, byte_offset_in_table) = reader.sb.inode_table_offset(ino);
    let gd = reader
        .read_group_desc(image, group)
        .expect("read group descriptor for inode");
    let table_start_byte = gd
        .inode_table
        .checked_mul(u64::from(reader.sb.block_size))
        .expect("inode table byte offset overflow");
    let inode_byte = table_start_byte
        .checked_add(byte_offset_in_table)
        .expect("inode byte offset overflow");
    let inode_offset = usize::try_from(inode_byte).expect("inode offset fits usize");
    let size_lo = u32::from_le_bytes(
        image[inode_offset + 0x04..inode_offset + 0x08]
            .try_into()
            .expect("size_lo slice"),
    );
    let size_hi = u32::from_le_bytes(
        image[inode_offset + 0x6C..inode_offset + 0x70]
            .try_into()
            .expect("size_hi slice"),
    );
    (size_lo, size_hi)
}

fn parse_reference_xattr_name(full_name: &str) -> (u8, Vec<u8>) {
    if let Some(name) = full_name.strip_prefix("user.") {
        return (EXT4_XATTR_INDEX_USER, name.as_bytes().to_vec());
    }
    if full_name == "system.posix_acl_access" {
        return (EXT4_XATTR_INDEX_POSIX_ACL_ACCESS, Vec::new());
    }
    if full_name == "system.posix_acl_default" {
        return (EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT, Vec::new());
    }
    if let Some(name) = full_name.strip_prefix("security.") {
        return (EXT4_XATTR_INDEX_SECURITY, name.as_bytes().to_vec());
    }
    panic!("unsupported reference xattr name {full_name}");
}

fn kernel_xattr_missing(image: &Path, path: &str, name: &str) -> bool {
    let out = Command::new("debugfs")
        .args(["-R", &format!("ea_get {path} {name}")])
        .arg(image)
        .output()
        .expect("run debugfs ea_get missing probe");
    String::from_utf8_lossy(&out.stderr).contains("Extended attribute key not found")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelDxHash {
    major: u32,
    minor: u32,
}

fn parse_dx_hash_line(line: &str) -> Option<KernelDxHash> {
    let major_marker = " is 0x";
    let major_start = line.find(major_marker)? + major_marker.len();
    let major_end = line[major_start..].find(' ')? + major_start;
    let minor_marker = "(minor 0x";
    let minor_start = line.find(minor_marker)? + minor_marker.len();
    let minor_end = line[minor_start..].find(')')? + minor_start;
    Some(KernelDxHash {
        major: u32::from_str_radix(&line[major_start..major_end], 16).ok()?,
        minor: u32::from_str_radix(&line[minor_start..minor_end], 16).ok()?,
    })
}

fn capture_dx_hash_batch(
    image: &Path,
    hash_alg: Option<&str>,
    names: &[String],
) -> Vec<KernelDxHash> {
    let mut commands = NamedTempFile::new().expect("create temp debugfs command file");
    for name in names {
        match hash_alg {
            Some(hash_alg) => {
                writeln!(commands, "dx_hash -h {hash_alg} {name}").expect("write dx_hash command");
            }
            None => writeln!(commands, "dx_hash {name}").expect("write dx_hash command"),
        }
    }
    commands.flush().expect("flush temp debugfs command file");

    let out = Command::new("debugfs")
        .args(["-f"])
        .arg(commands.path())
        .arg(image)
        .stderr(std::process::Stdio::null())
        .output()
        .expect("run debugfs dx_hash batch");
    assert!(out.status.success(), "debugfs dx_hash batch failed");

    let text = String::from_utf8_lossy(&out.stdout);
    let hashes: Vec<_> = text.lines().filter_map(parse_dx_hash_line).collect();
    assert_eq!(
        hashes.len(),
        names.len(),
        "expected {} dx_hash results, got {}.\n{text}",
        names.len(),
        hashes.len()
    );
    hashes
}

fn dx_hash_reference_corpus() -> Vec<String> {
    (0..1000)
        .map(|idx| {
            let family = match idx % 5 {
                0 => "alpha",
                1 => "BETA",
                2 => "gamma-branch",
                3 => "delta.segment",
                _ => "mix_42",
            };
            let repeated = "xyz".repeat((idx % 7) + 1);
            format!("{family}_{idx:04}_{repeated}.dat")
        })
        .collect()
}

// ── Golden JSON helpers ─────────────────────────────────────────

fn golden_path_named(file_name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance")
        .join("golden")
        .join(file_name)
}

fn load_golden_named(file_name: &str) -> GoldenReference {
    let text = std::fs::read_to_string(golden_path_named(file_name)).expect("read golden JSON");
    serde_json::from_str(&text).expect("parse golden JSON")
}

fn load_golden() -> GoldenReference {
    load_golden_named("ext4_8mb_reference.json")
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

fn assert_directory_block_checksums_match_reference(
    image: &[u8],
    reader: &Ext4ImageReader,
    path: &str,
) {
    let (ino, inode) = reader
        .resolve_path(image, path)
        .unwrap_or_else(|err| panic!("resolve {path}: {err}"));
    let ext4_ino = ino.to_ext4().expect("ext4 inode number").0;
    let csum_seed = reader.sb.csum_seed();
    let block_count = inode.size.div_ceil(u64::from(reader.sb.block_size));
    let mut verified_blocks = 0_u64;

    for logical_block in 0..block_count {
        let logical_block = u32::try_from(logical_block).expect("logical block fits in u32");
        let phys = reader
            .resolve_extent(image, &inode, logical_block)
            .unwrap_or_else(|err| panic!("resolve extent {path}:{logical_block}: {err}"))
            .unwrap_or_else(|| panic!("missing extent for {path} logical block {logical_block}"));
        let block = reader
            .read_block(image, ffs_types::BlockNumber(phys))
            .unwrap_or_else(|err| panic!("read block {path}:{logical_block}: {err}"));

        match verify_dir_block_checksum(block, csum_seed, ext4_ino, inode.generation) {
            Ok(()) => {}
            Err(ffs_types::ParseError::InvalidField {
                field: "dir_block_tail",
                ..
            }) if logical_block == 0 && inode.has_htree_index() && parse_dx_root(block).is_ok() => {
                continue;
            }
            Err(err) => panic!("verify_dir_block_checksum {path}:{logical_block}: {err}"),
        }

        let mut restamped = block.to_vec();
        stamp_dir_block_checksum(&mut restamped, csum_seed, ext4_ino, inode.generation);
        assert_eq!(
            restamped, block,
            "restamped checksum diverged from ext4 reference block for {path}:{logical_block}"
        );
        verified_blocks += 1;
    }

    assert!(
        verified_blocks > 0,
        "expected at least one directory block for {path}"
    );
}

fn assert_inode_checksum_matches_reference(image: &[u8], reader: &Ext4ImageReader, path: &str) {
    let (ino, _) = reader
        .resolve_path(image, path)
        .unwrap_or_else(|err| panic!("resolve {path}: {err}"));
    let (group, _index, byte_offset_in_table) = reader.sb.inode_table_offset(ino);
    let gd = reader
        .read_group_desc(image, group)
        .unwrap_or_else(|err| panic!("read group desc for {path}: {err}"));
    let inode_table_start = gd
        .inode_table
        .checked_mul(u64::from(reader.sb.block_size))
        .and_then(|offset| offset.checked_add(byte_offset_in_table))
        .unwrap_or_else(|| panic!("inode table offset overflow for {path}"));
    let inode_offset =
        usize::try_from(inode_table_start).unwrap_or_else(|_| panic!("inode offset too large"));
    let inode_size = usize::from(reader.sb.inode_size);
    let raw_inode = &image[inode_offset..inode_offset + inode_size];
    let ext4_ino = ino.to_ext4().expect("ext4 inode number").0;

    verify_inode_checksum(
        raw_inode,
        reader.sb.csum_seed(),
        ext4_ino,
        reader.sb.inode_size,
    )
    .unwrap_or_else(|err| panic!("verify_inode_checksum {path}: {err}"));
}

fn assert_extent_mapping_matches_kernel(
    image_path: &Path,
    image: &[u8],
    reader: &Ext4ImageReader,
    path: &str,
) {
    let kernel_blocks = capture_block_map(image_path, path);
    let kernel_extents = collapse_block_map_to_extents(&kernel_blocks);
    let (_, inode) = reader
        .resolve_path(image, path)
        .unwrap_or_else(|err| panic!("resolve {path}: {err}"));
    let extents = reader
        .collect_extents(image, &inode)
        .unwrap_or_else(|err| panic!("collect_extents {path}: {err}"));

    assert!(!extents.is_empty(), "{path}: expected at least one extent");
    assert!(
        extents.iter().all(|extent| !extent.is_unwritten()),
        "{path}: expected initialized extents for reference file"
    );
    assert_eq!(
        expand_ffs_extent_blocks(&extents),
        kernel_blocks,
        "{path}: debugfs blocks vs collect_extents block map mismatch"
    );
    assert_eq!(
        normalize_ffs_extent_map(&extents),
        kernel_extents,
        "{path}: debugfs blocks vs collect_extents extent ranges mismatch"
    );
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

fn assert_field_eq<T>(variant: &str, path: &str, field: &str, expected: &T, actual: &T)
where
    T: std::fmt::Debug + PartialEq,
{
    assert_eq!(
        expected, actual,
        "variant={variant} path={path} field={field} expected={expected:?} actual={actual:?}"
    );
}

#[derive(Clone, Copy)]
struct Ext4GoldenVariant {
    name: &'static str,
    golden_file: &'static str,
    temp_image_name: &'static str,
    create_image: fn(&Path) -> PathBuf,
}

fn ext4_golden_variants() -> [Ext4GoldenVariant; 5] {
    [
        Ext4GoldenVariant {
            name: "ext4_8mb_reference",
            golden_file: "ext4_8mb_reference.json",
            temp_image_name: "ffs_ref_variant_8mb.ext4",
            create_image: create_reference_image,
        },
        Ext4GoldenVariant {
            name: "ext4_64mb_reference",
            golden_file: "ext4_64mb_reference.json",
            temp_image_name: "ffs_ref_variant_64mb.ext4",
            create_image: create_large_reference_image,
        },
        Ext4GoldenVariant {
            name: "ext4_dir_index_reference",
            golden_file: "ext4_dir_index_reference.json",
            temp_image_name: "ffs_ref_variant_dir_index.ext4",
            create_image: create_dir_index_reference_image,
        },
        Ext4GoldenVariant {
            name: "ext4_64mb_sparse_super",
            golden_file: "ext4_64mb_sparse_super.json",
            temp_image_name: "ffs_ref_variant_sparse_super.ext4",
            create_image: create_sparse_super_golden_image,
        },
        Ext4GoldenVariant {
            name: "ext4_htree_dirindex",
            golden_file: "ext4_htree_dirindex.json",
            temp_image_name: "ffs_ref_variant_htree.ext4",
            create_image: create_htree_dirindex_golden_image,
        },
    ]
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

#[test]
fn ext4_large_isize_high_matches_debugfs_and_openfs() {
    const SCENARIO_ID: &str = "ext4_large_isize_high_kernel_reference";

    if !ext4_tools_available() {
        eprintln!(
            "SCENARIO_RESULT|scenario_id={SCENARIO_ID}|outcome=SKIP|detail=ext4_tools_unavailable_requires_mkfs_ext4_debugfs"
        );
        return;
    }

    let tmp = unique_temp_ext4_path("large_i_size_high");
    create_large_isize_high_reference_image(&tmp);

    let kernel = capture_debugfs_inode_stat(&tmp, LARGE_ISIZE_HIGH_PATH);
    assert_eq!(
        kernel.size, LARGE_ISIZE_HIGH_BYTES,
        "debugfs must preserve the >4GiB logical size"
    );

    let image = std::fs::read(&tmp).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse ext4 image");
    let ino = InodeNumber(kernel.inode_number);
    let (size_lo, size_hi) = raw_inode_size_words(&image, &reader, ino);
    assert_eq!(
        size_lo,
        u32::try_from(LARGE_ISIZE_HIGH_BYTES & 0xffff_ffff).expect("size_lo fits u32"),
        "raw i_size_lo must match low 32 bits"
    );
    assert_eq!(
        size_hi,
        u32::try_from(LARGE_ISIZE_HIGH_BYTES >> 32).expect("size_hi fits u32"),
        "raw i_size_high must carry upper 32 bits"
    );

    let (_, ondisk_inode) = reader
        .resolve_path(&image, LARGE_ISIZE_HIGH_PATH)
        .expect("resolve large sparse file");
    assert_eq!(
        ondisk_inode.size, kernel.size,
        "ffs_ondisk size must match debugfs"
    );

    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, &tmp, &OpenOptions::default())
        .expect("OpenFs should open sparse large-size ext4 image");
    let openfs_inode = fs.read_inode(&cx, ino).expect("OpenFs read_inode");
    assert_eq!(
        openfs_inode.size, kernel.size,
        "OpenFs read_inode size must match debugfs"
    );

    eprintln!(
        "SCENARIO_RESULT|scenario_id={SCENARIO_ID}|outcome=PASS|detail=file_size={};size_lo=0x{:08x};size_hi=0x{:08x};image_bytes={};seed_bytes={};inode={}",
        kernel.size,
        size_lo,
        size_hi,
        LARGE_ISIZE_HIGH_IMAGE_BYTES,
        LARGE_ISIZE_HIGH_SEED_BYTES,
        kernel.inode_number
    );

    std::fs::remove_file(&tmp).ok();
}

#[test]
#[allow(clippy::too_many_lines)]
fn ext4_kernel_vs_ffs_xattr_reference() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let tmp = std::env::temp_dir().join("ffs_ref_xattr_test.ext4");
    create_xattr_reference_image(&tmp);

    let image = std::fs::read(&tmp).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse ext4 image");

    for (path, expect_external) in [
        ("/xattrs/inline.txt", false),
        ("/xattrs/external.txt", true),
        ("/xattrs/acl_access.txt", false),
        ("/xattrs/acl_dir", false),
    ] {
        let kernel_attrs = capture_xattrs(&tmp, path);
        let (_, inode) = reader
            .resolve_path(&image, path)
            .unwrap_or_else(|err| panic!("resolve {path}: {err}"));

        let inline_attrs = normalize_ffs_xattrs(
            reader
                .read_xattrs_ibody(&inode)
                .unwrap_or_else(|err| panic!("read_xattrs_ibody {path}: {err}")),
        );
        let block_attrs = normalize_ffs_xattrs(
            reader
                .read_xattrs_block(&image, &inode)
                .unwrap_or_else(|err| panic!("read_xattrs_block {path}: {err}")),
        );
        let all_attrs = normalize_ffs_xattrs(
            reader
                .list_xattrs(&image, &inode)
                .unwrap_or_else(|err| panic!("list_xattrs {path}: {err}")),
        );

        if expect_external {
            assert_ne!(
                inode.file_acl, 0,
                "{path} should use an external xattr block"
            );
            assert!(
                inline_attrs.is_empty(),
                "{path} should not store test xattrs inline"
            );
            assert_eq!(block_attrs, kernel_attrs, "{path}: block xattrs mismatch");
        } else {
            assert_eq!(
                inode.file_acl, 0,
                "{path} should not use an external xattr block"
            );
            assert_eq!(inline_attrs, kernel_attrs, "{path}: inline xattrs mismatch");
            assert!(
                block_attrs.is_empty(),
                "{path} should not expose block xattrs"
            );
        }

        assert_eq!(all_attrs, kernel_attrs, "{path}: combined xattrs mismatch");

        for kernel_attr in &kernel_attrs {
            let (name_index, name) = parse_reference_xattr_name(&kernel_attr.name);
            let observed = reader
                .get_xattr(&image, &inode, name_index, &name)
                .unwrap_or_else(|err| panic!("get_xattr {path} {}: {err}", kernel_attr.name))
                .unwrap_or_else(|| panic!("missing xattr {} in ffs-ondisk", kernel_attr.name));
            if name_index == EXT4_XATTR_INDEX_POSIX_ACL_ACCESS
                || name_index == EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT
            {
                assert_eq!(
                    observed,
                    capture_xattr_raw_value(&tmp, path, &kernel_attr.name),
                    "{path}: get_xattr mismatch for {}",
                    kernel_attr.name
                );
            } else {
                assert_eq!(
                    String::from_utf8(observed)
                        .unwrap_or_else(|err| panic!("utf-8 xattr {}: {err}", kernel_attr.name)),
                    kernel_attr.value,
                    "{path}: get_xattr mismatch for {}",
                    kernel_attr.name
                );
            }
        }
    }

    let (_, acl_access_inode) = reader
        .resolve_path(&image, "/xattrs/acl_access.txt")
        .expect("resolve acl_access.txt");
    assert!(
        kernel_xattr_missing(&tmp, "/xattrs/acl_access.txt", "system.posix_acl_default"),
        "debugfs should report a missing default ACL on a regular file"
    );
    assert_eq!(
        reader
            .get_xattr(
                &image,
                &acl_access_inode,
                EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT,
                &[],
            )
            .expect("get_xattr missing default ACL"),
        None,
        "ffs-ondisk should report no default ACL on a regular file"
    );

    std::fs::remove_file(&tmp).ok();
}

#[test]
fn ext4_inline_data_continuation_kernel_reference() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let tmp = unique_temp_ext4_path("inline_data_continuation");
    create_inline_data_reference_image(&tmp);

    let image = std::fs::read(&tmp).expect("read inline-data reference image");
    let reader = Ext4ImageReader::new(&image).expect("parse inline-data ext4 image");
    let (ino, inode) = reader
        .resolve_path(&image, INLINE_DATA_CONTINUATION_PATH)
        .expect("resolve inline-data continuation reference path");
    let expected = inline_data_continuation_payload();

    assert_eq!(
        inode.flags & EXT4_INLINE_DATA_FL,
        EXT4_INLINE_DATA_FL,
        "debugfs reference file must use EXT4_INLINE_DATA_FL"
    );
    assert_eq!(
        inode.size,
        u64::try_from(expected.len()).expect("inline payload length fits u64"),
        "inline-data size"
    );
    assert_eq!(
        inode.blocks, 0,
        "inline-data file should allocate no data blocks"
    );
    assert_eq!(
        inode.file_acl, 0,
        "inline-data continuation should live in ibody, not external xattr block"
    );
    assert_eq!(
        &inode.extent_bytes[..60],
        &expected[..60],
        "i_block inline payload diverged from debugfs reference"
    );

    let xattrs = parse_ibody_xattrs(&inode).expect("parse ibody xattrs");
    let continuation = xattrs
        .iter()
        .find(|xattr| {
            xattr.name_index == EXT4_XATTR_INDEX_SYSTEM && xattr.name.as_slice() == b"data"
        })
        .expect("debugfs inline-data reference should contain system.data continuation");
    assert_eq!(
        continuation.value,
        expected[60..],
        "system.data continuation diverged from debugfs reference"
    );

    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, &tmp, &OpenOptions::default())
        .expect("open inline-data reference image through OpenFs");
    let full = fs
        .read(
            &cx,
            ino,
            0,
            u32::try_from(expected.len()).expect("inline payload length fits u32"),
        )
        .expect("read full inline-data continuation through OpenFs");
    assert_eq!(
        full, expected,
        "OpenFs inline-data read diverged from debugfs reference"
    );
    let tail = fs
        .read(&cx, ino, 56, 32)
        .expect("read inline-data continuation tail through OpenFs");
    assert_eq!(&tail, &expected[56..]);

    std::fs::remove_file(&tmp).ok();
}

#[test]
fn ext4_debugfs_vs_ffs_xattr_writer_reference() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let base_path = unique_temp_ext4_path("xattr_writer_base");
    let reference_path = unique_temp_ext4_path("xattr_writer_reference");

    create_xattr_base_image(&base_path);
    std::fs::copy(&base_path, &reference_path).expect("copy base xattr image");
    apply_xattr_reference_mutations(&reference_path);

    let base_image = std::fs::read(&base_path).expect("read base image");
    let reference_image = std::fs::read(&reference_path).expect("read reference image");

    let base_reader = Ext4ImageReader::new(&base_image).expect("parse base ext4 image");
    let reference_reader = Ext4ImageReader::new(&reference_image).expect("parse reference image");
    let access = xattr_writer_access();

    let inline_kernel_attrs = capture_xattrs(&reference_path, "/xattrs/inline.txt");
    let (_, mut inline_inode) = base_reader
        .resolve_path(&base_image, "/xattrs/inline.txt")
        .expect("resolve base inline.txt");
    let (_, reference_inline_inode) = reference_reader
        .resolve_path(&reference_image, "/xattrs/inline.txt")
        .expect("resolve reference inline.txt");

    let inline_storage = ffs_xattr::set_xattr(
        &mut inline_inode,
        None,
        "user.mime",
        INLINE_XATTR_USER_VALUE.as_bytes(),
        access,
    )
    .expect("write inline user xattr");
    assert_eq!(inline_storage, ffs_xattr::XattrStorage::Inline);
    let inline_storage = ffs_xattr::set_xattr(
        &mut inline_inode,
        None,
        "security.selinux",
        INLINE_XATTR_SECURITY_VALUE.as_bytes(),
        access,
    )
    .expect("write inline security xattr");
    assert_eq!(inline_storage, ffs_xattr::XattrStorage::Inline);
    assert_eq!(
        inline_inode.file_acl, reference_inline_inode.file_acl,
        "inline file_acl pointer mismatch"
    );
    assert_eq!(
        inline_inode.xattr_ibody, reference_inline_inode.xattr_ibody,
        "inline xattr ibody bytes diverged from debugfs reference"
    );
    assert_eq!(
        normalize_ffs_xattrs(
            parse_ibody_xattrs(&inline_inode).expect("parse written inline xattrs")
        ),
        inline_kernel_attrs,
        "inline written xattrs diverged from debugfs reference"
    );

    let external_kernel_attrs = capture_xattrs(&reference_path, "/xattrs/external.txt");
    let (_, mut external_inode) = base_reader
        .resolve_path(&base_image, "/xattrs/external.txt")
        .expect("resolve base external.txt");
    let (_, reference_external_inode) = reference_reader
        .resolve_path(&reference_image, "/xattrs/external.txt")
        .expect("resolve reference external.txt");
    external_inode.file_acl = reference_external_inode.file_acl;
    let mut external_block =
        vec![0_u8; usize::try_from(reference_reader.sb.block_size).expect("block size fits usize")];

    let external_value = "X".repeat(EXTERNAL_XATTR_VALUE_LEN);
    let external_storage = ffs_xattr::set_xattr(
        &mut external_inode,
        Some(&mut external_block),
        "user.big",
        external_value.as_bytes(),
        access,
    )
    .expect("write external xattr");
    assert_eq!(external_storage, ffs_xattr::XattrStorage::External);
    assert_eq!(
        external_inode.file_acl, reference_external_inode.file_acl,
        "external file_acl pointer mismatch"
    );
    assert_eq!(
        external_inode.xattr_ibody, reference_external_inode.xattr_ibody,
        "external inode ibody bytes diverged from debugfs reference"
    );
    assert_eq!(
        normalize_ffs_xattrs(
            parse_xattr_block(&external_block).expect("parse written external block")
        ),
        external_kernel_attrs,
        "external written xattrs diverged from debugfs reference"
    );

    let reference_block = reference_reader
        .read_block(
            &reference_image,
            BlockNumber(reference_external_inode.file_acl),
        )
        .expect("read reference external xattr block");
    assert_eq!(
        canonicalize_xattr_block_for_writer_reference(&external_block),
        canonicalize_xattr_block_for_writer_reference(reference_block),
        "external xattr block bytes diverged from debugfs reference after checksum normalization"
    );
}

/// E2E: compare `collect_extents` against `debugfs blocks` on contiguous and
/// deterministically fragmented reference files.
#[test]
fn ext4_kernel_vs_ffs_extent_mapping() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let simple = unique_temp_ext4_path("extent_reference_simple");
    create_reference_image(&simple);

    let simple_image = std::fs::read(&simple).expect("read image");
    let simple_reader = Ext4ImageReader::new(&simple_image).expect("parse ext4 image");
    for path in ["/testdir/hello.txt", "/readme.txt"] {
        assert_extent_mapping_matches_kernel(&simple, &simple_image, &simple_reader, path);
    }

    let fragmented = unique_temp_ext4_path("extent_reference_fragmented");
    create_fragmented_extent_reference_image(&fragmented);

    let fragmented_image = std::fs::read(&fragmented).expect("read fragmented image");
    let fragmented_reader =
        Ext4ImageReader::new(&fragmented_image).expect("parse fragmented ext4 image");
    for path in ["/frag/b.bin", "/frag/target.bin"] {
        assert_extent_mapping_matches_kernel(
            &fragmented,
            &fragmented_image,
            &fragmented_reader,
            path,
        );
    }

    std::fs::remove_file(&simple).ok();
    std::fs::remove_file(&fragmented).ok();
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
    assert_ne!(golden.directories, [] as [ffs_harness::GoldenDirectory; 0]);
    assert_ne!(golden.files, [] as [ffs_harness::GoldenFile; 0]);

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

/// E2E: each ext4 golden variant must match a freshly generated image.
///
/// This is the primary regression gate for ext4 golden variants. On mismatch,
/// assertions include explicit variant/path/field context.
fn assert_variant_superblock_fields(
    variant: &Ext4GoldenVariant,
    golden: &GoldenReference,
    reader: &Ext4ImageReader,
) {
    assert_field_eq(
        variant.name,
        "/",
        "superblock.block_size",
        &golden.superblock.block_size,
        &reader.sb.block_size,
    );
    assert_field_eq(
        variant.name,
        "/",
        "superblock.blocks_count",
        &golden.superblock.blocks_count,
        &reader.sb.blocks_count,
    );
    assert_field_eq(
        variant.name,
        "/",
        "superblock.inodes_count",
        &golden.superblock.inodes_count,
        &reader.sb.inodes_count,
    );
    assert_field_eq(
        variant.name,
        "/",
        "superblock.volume_name",
        &golden.superblock.volume_name,
        &reader.sb.volume_name,
    );
    assert_field_eq(
        variant.name,
        "/",
        "superblock.free_blocks_count",
        &golden.superblock.free_blocks_count,
        &reader.sb.free_blocks_count,
    );
    assert_field_eq(
        variant.name,
        "/",
        "superblock.free_inodes_count",
        &golden.superblock.free_inodes_count,
        &reader.sb.free_inodes_count,
    );
}

fn assert_variant_directory_fields(
    variant: &Ext4GoldenVariant,
    golden: &GoldenReference,
    reader: &Ext4ImageReader,
    image: &[u8],
) {
    for gdir in &golden.directories {
        let (_, inode) = reader
            .resolve_path(image, &gdir.path)
            .unwrap_or_else(|e| panic!("variant={} resolve {}: {e}", variant.name, gdir.path));
        let entries = reader
            .read_dir(image, &inode)
            .unwrap_or_else(|e| panic!("variant={} read_dir {}: {e}", variant.name, gdir.path));
        let mut actual: Vec<(String, String)> = entries
            .iter()
            .map(|e| (e.name_str(), ext4_dir_entry_type_str(e).to_string()))
            .collect();
        actual.sort_unstable();

        let mut expected: Vec<(String, String)> = gdir
            .entries
            .iter()
            .map(|e| (e.name.clone(), e.file_type.clone()))
            .collect();
        expected.sort_unstable();

        assert_field_eq(
            variant.name,
            &gdir.path,
            "directory.entries",
            &expected,
            &actual,
        );
    }
}

fn assert_variant_file_fields(
    variant: &Ext4GoldenVariant,
    golden: &GoldenReference,
    reader: &Ext4ImageReader,
    image: &[u8],
) {
    for gfile in &golden.files {
        let (_, inode) = reader
            .resolve_path(image, &gfile.path)
            .unwrap_or_else(|e| panic!("variant={} resolve {}: {e}", variant.name, gfile.path));
        assert_field_eq(
            variant.name,
            &gfile.path,
            "file.size",
            &gfile.size,
            &inode.size,
        );

        #[allow(clippy::cast_possible_truncation)]
        let mut buf = vec![0_u8; inode.size as usize];
        let n = reader
            .read_inode_data(image, &inode, 0, &mut buf)
            .unwrap_or_else(|e| panic!("variant={} read {}: {e}", variant.name, gfile.path));
        let actual_content = buf[..n].to_vec();
        assert_field_eq(
            variant.name,
            &gfile.path,
            "file.content",
            &gfile.content,
            &actual_content,
        );
    }
}

fn assert_variant_matches_generated_image(variant: &Ext4GoldenVariant) {
    let golden = load_golden_named(variant.golden_file);
    let tmp = std::env::temp_dir().join(variant.temp_image_name);

    eprintln!(
        "testing variant={} golden={} image={}",
        variant.name,
        variant.golden_file,
        tmp.display()
    );
    (variant.create_image)(&tmp);

    let image = std::fs::read(&tmp).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse ext4 image");

    assert_variant_superblock_fields(variant, &golden, &reader);
    assert_variant_directory_fields(variant, &golden, &reader, &image);
    assert_variant_file_fields(variant, &golden, &reader, &image);

    std::fs::remove_file(&tmp).ok();
}

#[test]
fn ext4_variant_goldens_match_generated_images() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    for variant in ext4_golden_variants() {
        assert_variant_matches_generated_image(&variant);
    }
}

#[test]
fn ext4_dir_index_reference_image_materializes_real_htree() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let tmp = std::env::temp_dir().join("ffs_ref_real_htree.ext4");
    create_dir_index_reference_image(&tmp);

    let image = std::fs::read(&tmp).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse ext4 image");
    assert_eq!(
        reader.sb.hash_seed,
        [0x1111_1111, 0x3333_2222, 0x5555_4444, 0x5555_5555],
        "dir_index reference image should pin the hash seed for reproducibility"
    );
    assert_eq!(
        reader.sb.def_hash_version, 1,
        "mkfs.ext4 dir_index reference should default to half_md4"
    );

    let (_, htree_inode) = reader
        .resolve_path(&image, "/htree")
        .expect("resolve /htree");
    assert!(
        htree_inode.has_htree_index(),
        "/htree should have EXT4_INDEX_FL after e2fsck -D"
    );

    let block0 = reader
        .resolve_extent(&image, &htree_inode, 0)
        .expect("resolve htree logical block 0")
        .expect("/htree should have a first data block");
    let dx_root = parse_dx_root(
        reader
            .read_block(&image, ffs_types::BlockNumber(block0))
            .expect("read htree root block"),
    )
    .expect("parse real dx_root");
    assert_eq!(dx_root.hash_version, reader.sb.def_hash_version);
    assert_eq!(dx_root.indirect_levels, 0);
    assert!(
        dx_root.entries.len() >= 2,
        "htree root should have at least a sentinel plus one leaf entry"
    );

    for name in ["file_000.txt", "file_090.txt", "file_179.txt"] {
        let entry = reader
            .htree_lookup(&image, &htree_inode, name.as_bytes())
            .unwrap_or_else(|err| panic!("htree_lookup {name}: {err}"))
            .unwrap_or_else(|| panic!("htree_lookup {name} should find an entry"));
        assert_eq!(entry.name_str(), name, "unexpected htree match for {name}");
    }

    std::fs::remove_file(&tmp).ok();
}

#[test]
fn ext4_kernel_vs_ffs_dx_hash_reference() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let tmp = std::env::temp_dir().join("ffs_ref_dx_hash.ext4");
    create_dir_index_reference_image(&tmp);

    let image = std::fs::read(&tmp).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse ext4 image");
    let corpus = dx_hash_reference_corpus();

    for (hash_alg, version) in [("legacy", 0_u8), ("half_md4", 1_u8), ("tea", 2_u8)] {
        let kernel_hashes = capture_dx_hash_batch(&tmp, Some(hash_alg), &corpus);
        for (name, kernel_hash) in corpus.iter().zip(kernel_hashes.iter()) {
            let actual = dx_hash(version, name.as_bytes(), &reader.sb.hash_seed);
            assert_eq!(
                actual,
                (kernel_hash.major, kernel_hash.minor),
                "dx_hash mismatch for alg={hash_alg} version={version} name={name}"
            );
        }
    }

    let default_hashes = capture_dx_hash_batch(&tmp, None, &corpus);
    for (name, kernel_hash) in corpus.iter().zip(default_hashes.iter()) {
        let actual = dx_hash(
            reader.sb.def_hash_version,
            name.as_bytes(),
            &reader.sb.hash_seed,
        );
        assert_eq!(
            actual,
            (kernel_hash.major, kernel_hash.minor),
            "default dx_hash mismatch for version={} name={name}",
            reader.sb.def_hash_version
        );
    }

    std::fs::remove_file(&tmp).ok();
}

#[test]
fn ext4_kernel_vs_ffs_dir_block_checksum_reference() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let simple = std::env::temp_dir().join("ffs_ref_dir_checksum.ext4");
    create_reference_image(&simple);

    let simple_image = std::fs::read(&simple).expect("read simple ext4 image");
    let simple_reader = Ext4ImageReader::new(&simple_image).expect("parse simple ext4 image");
    assert_directory_block_checksums_match_reference(&simple_image, &simple_reader, "/");
    assert_directory_block_checksums_match_reference(&simple_image, &simple_reader, "/testdir");

    let indexed = std::env::temp_dir().join("ffs_ref_dir_checksum_dx.ext4");
    create_dir_index_reference_image(&indexed);

    let indexed_image = std::fs::read(&indexed).expect("read indexed ext4 image");
    let indexed_reader = Ext4ImageReader::new(&indexed_image).expect("parse indexed ext4 image");
    assert_directory_block_checksums_match_reference(&indexed_image, &indexed_reader, "/");
    assert_directory_block_checksums_match_reference(&indexed_image, &indexed_reader, "/htree");
}

#[test]
fn ext4_kernel_vs_ffs_inode_checksum_reference() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let simple = std::env::temp_dir().join("ffs_ref_inode_checksum.ext4");
    create_reference_image(&simple);

    let simple_image = std::fs::read(&simple).expect("read simple ext4 image");
    let simple_reader = Ext4ImageReader::new(&simple_image).expect("parse simple ext4 image");
    for path in ["/", "/testdir", "/testdir/hello.txt", "/readme.txt"] {
        assert_inode_checksum_matches_reference(&simple_image, &simple_reader, path);
    }

    let indexed = std::env::temp_dir().join("ffs_ref_inode_checksum_dx.ext4");
    create_dir_index_reference_image(&indexed);

    let indexed_image = std::fs::read(&indexed).expect("read indexed ext4 image");
    let indexed_reader = Ext4ImageReader::new(&indexed_image).expect("parse indexed ext4 image");
    for path in ["/", "/htree", "/htree/file_000.txt", "/htree/file_179.txt"] {
        assert_inode_checksum_matches_reference(&indexed_image, &indexed_reader, path);
    }
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
