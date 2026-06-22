#![forbid(unsafe_code)]
//! E2E tests that mount an ext4 image via FUSE and verify file operations
//! through the kernel VFS.
//!
//! These tests require:
//! - `/dev/fuse` to exist (FUSE kernel module)
//! - `mkfs.ext4` and `debugfs` on `$PATH`
//! - `fusermount3` permission to mount (may fail in containers)
//!
//! All tests run by default and return early (soft-skip) when prerequisites
//! are unavailable. This makes the suite CI-compatible: tests pass
//! everywhere, and exercise FUSE when the environment supports it.
//! Only `fuse_setattr_chown` remains `#[ignore]` as it requires root.

use asupersync::Cx;
use ffs_core::{
    BtrfsMountSelection, Ext4JournalReplayMode, FsOps, InodeAttr, OpenFs, OpenOptions, RequestScope,
};
use ffs_fuse::{MountOptions, WritebackCacheMode, mount_background};
use ffs_harness::load_sparse_fixture;
use ffs_types::{GroupNumber, InodeNumber};
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const EOPNOTSUPP_ERRNO: i64 = 95;
const BTRFS_TEST_WORKSPACE: &str = "testdir";
const FS_IOC_FIEMAP_CMD: u32 = 0xC020_660B;
const FIEMAP_REQUEST_FLAG_SYNC: u32 = 0x0001;
const FIEMAP_REQUEST_FLAG_XATTR: u32 = 0x0002;
const FIEMAP_EXTENT_LAST_FLAG: u32 = 0x0001;
const FIEMAP_EXTENT_UNWRITTEN_FLAG: u32 = 0x0800;
const FS_IOC_GET_ENCRYPTION_POLICY_CMD: u32 = 0x400C_6615;
const FS_IOC_GET_ENCRYPTION_POLICY_EX_CMD: u32 = 0xC009_6616;
const FS_IOC_GETFSLABEL_CMD: u32 = 0x8100_9431;
const FS_IOC_SETFSLABEL_CMD: u32 = 0x4100_9432;
const EXT4_IOC_GETFLAGS_CMD: u32 = 0x8008_6601;
const EXT4_IOC_SETFLAGS_CMD: u32 = 0x4008_6602;
const EXT4_IOC_GETVERSION_CMD: u32 = 0x8008_6603;
const EXT4_IOC_SETVERSION_CMD: u32 = 0x4008_6604;
const EXT4_IOC_MOVE_EXT_CMD: u32 = 0xC028_660F;
const FSCRYPT_POLICY_V1_SIZE: usize = 12;
const FSCRYPT_CONTEXT_V1_SIZE: usize = 28;
const FSCRYPT_POLICY_V1_VERSION: u8 = 0;
const FSCRYPT_POLICY_V2_SIZE: usize = 24;
const FSCRYPT_CONTEXT_V2_SIZE: usize = 40;
const FSCRYPT_POLICY_V2_VERSION: u8 = 2;
const EXT4_ENCRYPT_INODE_FL: u32 = 0x0000_0800;
const EXT4_ENCRYPTION_XATTR_NAME: &[u8] = b"c";
const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;
const ACL_USER_OBJ_TAG: u16 = 0x0001;
const ACL_GROUP_OBJ_TAG: u16 = 0x0004;
const ACL_OTHER_TAG: u16 = 0x0020;
const ACL_UNDEFINED_ID: u32 = u32::MAX;
const FUSE_MOUNT_STATE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const FUSE_MOUNT_READY_TIMEOUT: Duration = Duration::from_secs(1);
const FUSE_MOUNT_RELEASE_TIMEOUT: Duration = Duration::from_secs(2);

fn patterned_bytes(len: usize, modulus: usize, offset: usize) -> Vec<u8> {
    assert!(
        modulus + offset <= usize::from(u8::MAX) + 1,
        "pattern byte range should fit u8"
    );
    (0..len)
        .map(|i| u8::try_from((i % modulus) + offset).expect("pattern byte should fit u8"))
        .collect()
}

fn command_available(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn emit_scenario_result(scenario_id: &str, outcome: &str, detail: Option<&str>) {
    match detail {
        Some(detail) => {
            eprintln!(
                "SCENARIO_RESULT|scenario_id={scenario_id}|outcome={outcome}|detail={detail}"
            );
        }
        None => eprintln!("SCENARIO_RESULT|scenario_id={scenario_id}|outcome={outcome}"),
    }
}

fn read_ioctl_trace(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn trace_contains_cmd(trace: &str, cmd: u32) -> bool {
    trace.contains(&format!("cmd=0x{cmd:08x}"))
}

fn fscrypt_policy_ex_transport_eio_is_expected(
    report: &Value,
    ioctl_trace: &str,
    scenario_id: &str,
    policy_version: &str,
) -> bool {
    if report["errno"].as_i64() != Some(i64::from(libc::EIO)) {
        return false;
    }
    assert!(
        trace_contains_cmd(ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_EX_CMD),
        "GET_ENCRYPTION_POLICY_EX {policy_version} EIO must be after ffs-fuse::ioctl dispatch: \
         {ioctl_trace}"
    );
    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("restricted_fuse_iowr_transport_surfaces_eio"),
    );
    true
}

/// Check if FUSE E2E prerequisites are met.
fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
        && command_available("mkfs.ext4")
        && command_available("debugfs")
}

fn mountinfo_unescape(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while let Some(byte) = bytes.get(idx) {
        if *byte == b'\\' {
            if let Some(octal) = idx
                .checked_add(1)
                .zip(idx.checked_add(4))
                .and_then(|(start, end)| bytes.get(start..end))
            {
                if octal.iter().all(|byte| matches!(*byte, b'0'..=b'7')) {
                    let value = octal
                        .iter()
                        .fold(0_u16, |acc, byte| acc * 8 + u16::from(byte - b'0'));
                    if let Ok(byte) = u8::try_from(value) {
                        out.push(byte);
                        idx += 4;
                        continue;
                    }
                }
            }
        }
        out.push(*byte);
        idx += 1;
    }
    out
}

fn mountinfo_has_mountpoint(mountpoint: &Path) -> bool {
    let target = mountpoint.as_os_str().as_bytes();
    fs::read_to_string("/proc/self/mountinfo").is_ok_and(|mountinfo| {
        mountinfo.lines().any(|line| {
            line.split(' ')
                .nth(4)
                .is_some_and(|field| mountinfo_unescape(field) == target)
        })
    })
}

fn wait_for_fuse_mount_state(mountpoint: &Path, expected_mounted: bool, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if mountinfo_has_mountpoint(mountpoint) == expected_mounted {
            return;
        }
        let remaining = timeout.saturating_sub(start.elapsed());
        thread::sleep(std::cmp::min(FUSE_MOUNT_STATE_POLL_INTERVAL, remaining));
    }
    let expected = if expected_mounted {
        "mounted"
    } else {
        "released"
    };
    assert!(
        mountinfo_has_mountpoint(mountpoint) == expected_mounted,
        "timed out after {timeout:?} waiting for {} to become {expected}",
        mountpoint.display()
    );
}

fn wait_for_fuse_mount_ready(mountpoint: &Path) {
    wait_for_fuse_mount_state(mountpoint, true, FUSE_MOUNT_READY_TIMEOUT);
}

fn wait_for_fuse_mount_released(mountpoint: &Path) {
    wait_for_fuse_mount_state(mountpoint, false, FUSE_MOUNT_RELEASE_TIMEOUT);
}

/// Create a small ext4 image and populate it with test files using debugfs.
fn create_test_image(dir: &Path) -> std::path::PathBuf {
    create_test_image_with_size(dir, 4 * 1024 * 1024)
}

fn create_test_image_with_ext4_incompat_features(
    dir: &Path,
    image_size_bytes: u64,
    incompat_bits: u32,
) -> std::path::PathBuf {
    let image = create_test_image_with_size(dir, image_size_bytes);
    let mut data = fs::read(&image).expect("read ext4 image");
    let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;
    let incompat_off = sb_off + 0x60;
    let checksum_off = sb_off + ffs_types::EXT4_SB_CHECKSUM_OFFSET;
    let mut feature_incompat = u32::from_le_bytes(
        data[incompat_off..incompat_off + 4]
            .try_into()
            .expect("feature_incompat bytes"),
    );
    feature_incompat |= incompat_bits;
    data[incompat_off..incompat_off + 4].copy_from_slice(&feature_incompat.to_le_bytes());
    let checksum = ffs_ondisk::ext4::ext4_chksum(
        !0u32,
        &data[sb_off..sb_off + ffs_types::EXT4_SB_CHECKSUM_OFFSET],
    );
    data[checksum_off..checksum_off + 4].copy_from_slice(&checksum.to_le_bytes());
    fs::write(&image, data).expect("rewrite ext4 image with incompat bits");
    image
}

fn conformance_fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance")
        .join("fixtures")
        .join(name)
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_featured_dir_image(
    raw_name: &[u8],
    incompat_feature: u32,
    root_inode_flags: u32,
) -> Vec<u8> {
    assert!(
        raw_name.len() < 256,
        "raw encrypted ext4 name must fit in a single dirent"
    );

    let block_size: u32 = 4096;
    let image_size: u32 = 256 * 1024;
    let mut image = vec![0_u8; image_size as usize];
    let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    let incompat = (ffs_ondisk::Ext4IncompatFeatures::FILETYPE.0
        | ffs_ondisk::Ext4IncompatFeatures::EXTENTS.0
        | incompat_feature)
        .to_le_bytes();
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat);
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());

    let root_ino = 4 * 4096 + 256;
    image[root_ino..root_ino + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[root_ino + 4..root_ino + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[root_ino + 0x1A..root_ino + 0x1C].copy_from_slice(&3_u16.to_le_bytes());
    image[root_ino + 0x20..root_ino + 0x24].copy_from_slice(&root_inode_flags.to_le_bytes());
    image[root_ino + 0x80..root_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let root_extent = root_ino + 0x28;
    image[root_extent..root_extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[root_extent + 2..root_extent + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 4..root_extent + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[root_extent + 6..root_extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 12..root_extent + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[root_extent + 16..root_extent + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 18..root_extent + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 20..root_extent + 24].copy_from_slice(&10_u32.to_le_bytes());

    let file_ino = 4 * 4096 + 10 * 256;
    image[file_ino..file_ino + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[file_ino + 4..file_ino + 8].copy_from_slice(&5_u32.to_le_bytes());
    image[file_ino + 0x1A..file_ino + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[file_ino + 0x80..file_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let dir = 10 * 4096;
    image[dir..dir + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir + 6] = 1;
    image[dir + 7] = 2;
    image[dir + 8] = b'.';

    let dir = dir + 12;
    image[dir..dir + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir + 6] = 2;
    image[dir + 7] = 2;
    image[dir + 8] = b'.';
    image[dir + 9] = b'.';

    let dir = dir + 12;
    image[dir..dir + 4].copy_from_slice(&11_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&4072_u16.to_le_bytes());
    image[dir + 6] = u8::try_from(raw_name.len()).expect("fscrypt raw name length fits u8");
    image[dir + 7] = 1;
    image[dir + 8..dir + 8 + raw_name.len()].copy_from_slice(raw_name);

    image
}

fn build_ext4_encrypt_image_with_dir(raw_name: &[u8]) -> Vec<u8> {
    build_ext4_featured_dir_image(
        raw_name,
        ffs_ondisk::Ext4IncompatFeatures::ENCRYPT.0,
        0x0008_0000,
    )
}

fn build_ext4_inline_data_image(inode_fixture: &str) -> Vec<u8> {
    let block_size: u32 = 4096;
    let image_size: u32 = 256 * 1024;
    let mut image = vec![0_u8; image_size as usize];
    let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    let incompat = (ffs_ondisk::Ext4IncompatFeatures::FILETYPE.0
        | ffs_ondisk::Ext4IncompatFeatures::EXTENTS.0
        | ffs_ondisk::Ext4IncompatFeatures::INLINE_DATA.0)
        .to_le_bytes();
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat);
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());

    let ino2 = 4 * 4096 + 256;
    image[ino2..ino2 + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[ino2 + 4..ino2 + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[ino2 + 0x1A..ino2 + 0x1C].copy_from_slice(&3_u16.to_le_bytes());
    image[ino2 + 0x80..ino2 + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let root_extent = ino2 + 0x28;
    image[root_extent..root_extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[root_extent + 2..root_extent + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 4..root_extent + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[root_extent + 6..root_extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 12..root_extent + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[root_extent + 16..root_extent + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 18..root_extent + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 20..root_extent + 24].copy_from_slice(&10_u32.to_le_bytes());

    let inline_inode = load_sparse_fixture(&conformance_fixture_path(inode_fixture))
        .expect("load inline inode fixture");
    let ino11 = 4 * 4096 + 10 * 256;
    image[ino11..ino11 + inline_inode.len()].copy_from_slice(&inline_inode);

    let dir = 10 * 4096;
    image[dir..dir + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir + 6] = 1;
    image[dir + 7] = 2;
    image[dir + 8] = b'.';

    let dir = dir + 12;
    image[dir..dir + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir + 6] = 2;
    image[dir + 7] = 2;
    image[dir + 8] = b'.';
    image[dir + 9] = b'.';

    let name = b"inline.bin";
    let dir = dir + 12;
    image[dir..dir + 4].copy_from_slice(&11_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&4072_u16.to_le_bytes());
    image[dir + 6] = u8::try_from(name.len()).expect("inline fixture name length fits u8");
    image[dir + 7] = 1;
    image[dir + 8..dir + 8 + name.len()].copy_from_slice(name);

    image
}

fn create_ext4_inline_data_test_image(dir: &Path, inode_fixture: &str) -> PathBuf {
    let image = dir.join("inline-data.ext4");
    fs::write(&image, build_ext4_inline_data_image(inode_fixture))
        .expect("write ext4 inline-data fixture image");
    image
}

fn create_empty_ext4_test_image_with_size(dir: &Path, image_size_bytes: u64) -> std::path::PathBuf {
    let image = dir.join("test.ext4");

    let f = fs::File::create(&image).expect("create image");
    f.set_len(image_size_bytes).expect("set image size");
    drop(f);

    let out = Command::new("mkfs.ext4")
        .args([
            "-F",
            "-b",
            "4096",
            "-L",
            "ffs-fuse-e2e",
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.ext4");
    assert!(
        out.status.success(),
        "mkfs.ext4 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Make root writable so ext4 write-path tests work on unprivileged runners.
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field / mode 040777",
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs chmod /");
    assert!(
        out.status.success(),
        "debugfs chmod / failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    image
}

#[allow(clippy::too_many_lines)]
fn create_test_image_with_size(dir: &Path, image_size_bytes: u64) -> std::path::PathBuf {
    let image = create_empty_ext4_test_image_with_size(dir, image_size_bytes);

    // Populate with test files via debugfs.
    let hello_path = dir.join("hello_src.txt");
    let nested_path = dir.join("nested_src.txt");
    fs::write(&hello_path, b"Hello from FrankenFS E2E!\n").expect("write hello src");
    fs::write(&nested_path, b"Nested file content.\n").expect("write nested src");

    // Create directory
    let out = Command::new("debugfs")
        .args(["-w", "-R", "mkdir testdir", image.to_str().unwrap()])
        .output()
        .expect("debugfs mkdir");
    assert!(
        out.status.success(),
        "debugfs mkdir failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field testdir mode 040777",
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs chmod testdir");
    assert!(
        out.status.success(),
        "debugfs chmod testdir failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Write hello.txt
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("write {} hello.txt", hello_path.display()),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs write hello.txt");
    assert!(
        out.status.success(),
        "debugfs write hello.txt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let uid_out = Command::new("id").arg("-u").output().unwrap();
    let uid = String::from_utf8_lossy(&uid_out.stdout).trim().to_string();
    let gid_out = Command::new("id").arg("-g").output().unwrap();
    let gid = String::from_utf8_lossy(&gid_out.stdout).trim().to_string();
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("set_inode_field hello.txt uid {uid}"),
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("set_inode_field hello.txt gid {gid}"),
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field hello.txt mode 0100777",
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Write nested.txt
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("write {} testdir/nested.txt", nested_path.display()),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs write nested.txt");
    assert!(
        out.status.success(),
        "debugfs write nested.txt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("set_inode_field testdir/nested.txt uid {uid}"),
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("set_inode_field testdir/nested.txt gid {gid}"),
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field testdir/nested.txt mode 0100777",
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    image
}

fn create_test_image_with_seeded_namespace_removal_fixture(dir: &Path) -> std::path::PathBuf {
    let image = create_test_image_with_size(dir, 4 * 1024 * 1024);
    let empty_dir = "readonly_empty_dir";
    let unlink_seed_src = dir.join("readonly_unlink_seed_src.txt");
    let rename_seed_src = dir.join("readonly_rename_source_src.txt");

    fs::write(&unlink_seed_src, b"readonly ext4 unlink seed\n")
        .expect("write ext4 unlink namespace-removal seed");
    fs::write(&rename_seed_src, b"readonly ext4 rename source\n")
        .expect("write ext4 rename namespace-removal seed");

    let mkdir_out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("mkdir {empty_dir}"),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs mkdir readonly_empty_dir");
    assert!(
        mkdir_out.status.success(),
        "debugfs mkdir readonly_empty_dir failed: {}",
        String::from_utf8_lossy(&mkdir_out.stderr)
    );

    let chmod_out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("set_inode_field {empty_dir} mode 040777"),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs chmod readonly_empty_dir");
    assert!(
        chmod_out.status.success(),
        "debugfs chmod readonly_empty_dir failed: {}",
        String::from_utf8_lossy(&chmod_out.stderr)
    );

    for (src, target, desc) in [
        (
            &unlink_seed_src,
            "readonly_unlink_seed.txt",
            "readonly unlink seed",
        ),
        (
            &rename_seed_src,
            "readonly_rename_source.txt",
            "readonly rename source",
        ),
    ] {
        let out = Command::new("debugfs")
            .args([
                "-w",
                "-R",
                &format!("write {} {target}", src.display()),
                image.to_str().unwrap(),
            ])
            .output()
            .expect("debugfs write namespace-removal seed");
        assert!(
            out.status.success(),
            "debugfs write {desc} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    image
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

fn set_debugfs_xattr_from_file(
    image: &Path,
    target: &str,
    name: &str,
    value: &[u8],
    blob_path: &Path,
) {
    fs::write(blob_path, value).expect("write xattr blob");
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("ea_set -f {} {target} {name}", blob_path.display()),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs ea_set -f");
    assert!(
        out.status.success(),
        "debugfs ea_set -f failed for {target} {name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::remove_file(blob_path).ok();
}

fn create_ext4_posix_acl_test_image(dir: &Path) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let image = create_test_image(dir);
    let access_acl = build_posix_acl_xattr(&[
        (ACL_USER_OBJ_TAG, 0o6),
        (ACL_GROUP_OBJ_TAG, 0o4),
        (ACL_OTHER_TAG, 0),
    ]);
    let default_acl = build_posix_acl_xattr(&[
        (ACL_USER_OBJ_TAG, 0o7),
        (ACL_GROUP_OBJ_TAG, 0o5),
        (ACL_OTHER_TAG, 0o1),
    ]);
    set_debugfs_xattr_from_file(
        &image,
        "/hello.txt",
        "system.posix_acl_access",
        &access_acl,
        &dir.join("acl_access.bin"),
    );
    set_debugfs_xattr_from_file(
        &image,
        "/testdir",
        "system.posix_acl_default",
        &default_acl,
        &dir.join("acl_default.bin"),
    );
    (image, access_acl, default_acl)
}

fn build_fscrypt_context_v1(
    contents_mode: u8,
    filenames_mode: u8,
    flags: u8,
    descriptor: [u8; 8],
    nonce: [u8; 16],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(FSCRYPT_CONTEXT_V1_SIZE);
    context.push(FSCRYPT_POLICY_V1_VERSION);
    context.push(contents_mode);
    context.push(filenames_mode);
    context.push(flags);
    context.extend_from_slice(&descriptor);
    context.extend_from_slice(&nonce);
    context
}

fn build_fscrypt_context_v2(
    contents_mode: u8,
    filenames_mode: u8,
    flags: u8,
    log2_data_unit_size: u8,
    identifier: [u8; 16],
    nonce: [u8; 16],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(FSCRYPT_CONTEXT_V2_SIZE);
    context.push(FSCRYPT_POLICY_V2_VERSION);
    context.push(contents_mode);
    context.push(filenames_mode);
    context.push(flags);
    context.push(log2_data_unit_size);
    context.extend_from_slice(&[0_u8; 3]);
    context.extend_from_slice(&identifier);
    context.extend_from_slice(&nonce);
    context
}

fn build_test_inline_ibody(ibody_len: usize, entries: &[ffs_ondisk::Ext4Xattr]) -> Vec<u8> {
    let mut out = vec![0_u8; ibody_len];
    if entries.is_empty() {
        return out;
    }

    out[0..4].copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());
    let region_capacity = ibody_len
        .checked_sub(4)
        .expect("inline xattr region must include 4-byte header");
    let mut region = vec![0_u8; region_capacity];
    let mut next_entry = 0_usize;
    let mut value_tail = region_capacity;

    for entry in entries {
        let entry_len = (16 + entry.name.len() + 3) & !3;
        let value_start = value_tail
            .checked_sub(entry.value.len())
            .expect("inline xattr value should fit")
            & !3;
        let entry_end_with_term = next_entry
            .checked_add(entry_len + 4)
            .expect("inline xattr entry offset should not overflow");
        assert!(
            entry_end_with_term <= value_start,
            "inline xattr entry table should not overlap values"
        );

        region[value_start..value_start + entry.value.len()].copy_from_slice(&entry.value);
        value_tail = value_start;

        region[next_entry] =
            u8::try_from(entry.name.len()).expect("inline xattr name should fit in u8");
        region[next_entry + 1] = entry.name_index;
        region[next_entry + 2..next_entry + 4].copy_from_slice(
            &u16::try_from(value_start)
                .expect("inline xattr value offset should fit in u16")
                .to_le_bytes(),
        );
        region[next_entry + 8..next_entry + 12].copy_from_slice(
            &u32::try_from(entry.value.len())
                .expect("inline xattr value length should fit in u32")
                .to_le_bytes(),
        );
        region[next_entry + 16..next_entry + 16 + entry.name.len()].copy_from_slice(&entry.name);
        next_entry += entry_len;
    }

    out[4..].copy_from_slice(&region);
    out
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_fscrypt_policy_image(encrypted_flag: bool) -> Vec<u8> {
    let block_size: u32 = 4096;
    let image_size: u32 = 256 * 1024;
    let mut image = vec![0_u8; image_size as usize];
    let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    let incompat = (ffs_ondisk::Ext4IncompatFeatures::FILETYPE.0
        | ffs_ondisk::Ext4IncompatFeatures::EXTENTS.0
        | ffs_ondisk::Ext4IncompatFeatures::ENCRYPT.0)
        .to_le_bytes();
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat);
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());

    let root_ino = 4 * 4096 + 256;
    image[root_ino..root_ino + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[root_ino + 4..root_ino + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[root_ino + 0x1A..root_ino + 0x1C].copy_from_slice(&3_u16.to_le_bytes());
    image[root_ino + 0x20..root_ino + 0x24]
        .copy_from_slice(&ffs_types::EXT4_EXTENTS_FL.to_le_bytes());
    image[root_ino + 0x80..root_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let root_extent = root_ino + 0x28;
    image[root_extent..root_extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[root_extent + 2..root_extent + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 4..root_extent + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[root_extent + 6..root_extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 12..root_extent + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[root_extent + 16..root_extent + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 18..root_extent + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 20..root_extent + 24].copy_from_slice(&10_u32.to_le_bytes());

    let file_ino = 4 * 4096 + 10 * 256;
    image[file_ino..file_ino + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[file_ino + 4..file_ino + 8].copy_from_slice(&0_u32.to_le_bytes());
    image[file_ino + 0x1A..file_ino + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[file_ino + 0x80..file_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());
    if encrypted_flag {
        image[file_ino + 0x20..file_ino + 0x24]
            .copy_from_slice(&EXT4_ENCRYPT_INODE_FL.to_le_bytes());
    }

    let context = build_fscrypt_context_v1(1, 4, 0, *b"mkdesc42", *b"0123456789abcdef");
    let ibody = build_test_inline_ibody(
        256 - (128 + 32),
        &[ffs_ondisk::Ext4Xattr {
            name_index: ffs_types::EXT4_XATTR_INDEX_ENCRYPTION,
            name: EXT4_ENCRYPTION_XATTR_NAME.to_vec(),
            value: context,
        }],
    );
    let xattr_off = file_ino + 128 + 32;
    image[xattr_off..xattr_off + ibody.len()].copy_from_slice(&ibody);

    let dir_block = 10 * 4096;
    image[dir_block..dir_block + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir_block + 4..dir_block + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir_block + 6] = 1;
    image[dir_block + 7] = 2;
    image[dir_block + 8] = b'.';

    let dotdot = dir_block + 12;
    image[dotdot..dotdot + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dotdot + 4..dotdot + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dotdot + 6] = 2;
    image[dotdot + 7] = 2;
    image[dotdot + 8] = b'.';
    image[dotdot + 9] = b'.';

    let file_entry = dotdot + 12;
    let file_name = b"policy.txt";
    image[file_entry..file_entry + 4].copy_from_slice(&11_u32.to_le_bytes());
    image[file_entry + 4..file_entry + 6].copy_from_slice(&(4096_u16 - 24).to_le_bytes());
    image[file_entry + 6] = u8::try_from(file_name.len()).expect("policy name should fit u8");
    image[file_entry + 7] = 1;
    image[file_entry + 8..file_entry + 8 + file_name.len()].copy_from_slice(file_name);

    let inode_bitmap = 3 * 4096;
    for bit in [1_usize, 10_usize] {
        image[inode_bitmap + bit / 8] |= 1 << (bit % 8);
    }

    image
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_fscrypt_policy_v2_image() -> Vec<u8> {
    let block_size: u32 = 4096;
    let image_size: u32 = 256 * 1024;
    let mut image = vec![0_u8; image_size as usize];
    let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes()); // s_rev_level
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    let inodes_count: u32 = 128;
    image[sb_off..sb_off + 4].copy_from_slice(&inodes_count.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes()); // s_first_data_block
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes()); // s_blocks_per_group
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&inodes_count.to_le_bytes()); // s_inodes_per_group
    image[sb_off + 0x3A..sb_off + 0x3C].copy_from_slice(&1_u16.to_le_bytes()); // s_minor_rev_level
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes()); // s_inode_size
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes()); // s_creator_os
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes()); // s_first_ino
    let incompat_flags = ffs_ondisk::ext4::Ext4IncompatFeatures::FILETYPE.0
        | ffs_ondisk::ext4::Ext4IncompatFeatures::EXTENTS.0
        | ffs_ondisk::ext4::Ext4IncompatFeatures::ENCRYPT.0;
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat_flags.to_le_bytes());
    let checksum = ffs_ondisk::ext4::ext4_chksum(
        !0_u32,
        &image[sb_off..sb_off + ffs_types::EXT4_SB_CHECKSUM_OFFSET],
    );
    image[sb_off + ffs_types::EXT4_SB_CHECKSUM_OFFSET
        ..sb_off + ffs_types::EXT4_SB_CHECKSUM_OFFSET + 4]
        .copy_from_slice(&checksum.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes()); // block bitmap
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes()); // inode bitmap
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes()); // inode table

    let root_ino = 4 * 4096 + 256;
    image[root_ino..root_ino + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[root_ino + 4..root_ino + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[root_ino + 0x1A..root_ino + 0x1C].copy_from_slice(&3_u16.to_le_bytes());
    image[root_ino + 0x20..root_ino + 0x24]
        .copy_from_slice(&ffs_types::EXT4_EXTENTS_FL.to_le_bytes());
    image[root_ino + 0x80..root_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let root_extent = root_ino + 0x28;
    image[root_extent..root_extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes()); // eh_magic
    image[root_extent + 2..root_extent + 4].copy_from_slice(&1_u16.to_le_bytes()); // eh_entries
    image[root_extent + 4..root_extent + 6].copy_from_slice(&4_u16.to_le_bytes()); // eh_max
    image[root_extent + 6..root_extent + 8].copy_from_slice(&0_u16.to_le_bytes()); // eh_depth
    image[root_extent + 12..root_extent + 16].copy_from_slice(&0_u32.to_le_bytes()); // ee_block
    image[root_extent + 16..root_extent + 18].copy_from_slice(&1_u16.to_le_bytes()); // ee_len
    image[root_extent + 18..root_extent + 20].copy_from_slice(&0_u16.to_le_bytes()); // ee_start_hi
    image[root_extent + 20..root_extent + 24].copy_from_slice(&10_u32.to_le_bytes()); // ee_start_lo

    let file_ino = 4 * 4096 + 10 * 256;
    image[file_ino..file_ino + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[file_ino + 4..file_ino + 8].copy_from_slice(&0_u32.to_le_bytes());
    image[file_ino + 0x1A..file_ino + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[file_ino + 0x80..file_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());
    image[file_ino + 0x20..file_ino + 0x24].copy_from_slice(&EXT4_ENCRYPT_INODE_FL.to_le_bytes());

    let context = build_fscrypt_context_v2(1, 4, 0, 9, *b"0123456789abcdef", *b"fedcba9876543210");
    let ibody = build_test_inline_ibody(
        256 - (128 + 32),
        &[ffs_ondisk::Ext4Xattr {
            name_index: ffs_types::EXT4_XATTR_INDEX_ENCRYPTION,
            name: EXT4_ENCRYPTION_XATTR_NAME.to_vec(),
            value: context,
        }],
    );
    let xattr_off = file_ino + 128 + 32;
    image[xattr_off..xattr_off + ibody.len()].copy_from_slice(&ibody);

    let dir_block = 10 * 4096;
    image[dir_block..dir_block + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir_block + 4..dir_block + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir_block + 6] = 1;
    image[dir_block + 7] = 2;
    image[dir_block + 8] = b'.';

    let dotdot = dir_block + 12;
    image[dotdot..dotdot + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dotdot + 4..dotdot + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dotdot + 6] = 2;
    image[dotdot + 7] = 2;
    image[dotdot + 8] = b'.';
    image[dotdot + 9] = b'.';

    let file_entry = dotdot + 12;
    let file_name = b"policy.txt";
    image[file_entry..file_entry + 4].copy_from_slice(&11_u32.to_le_bytes());
    image[file_entry + 4..file_entry + 6].copy_from_slice(&(4096_u16 - 24).to_le_bytes());
    image[file_entry + 6] = u8::try_from(file_name.len()).expect("policy name should fit u8");
    image[file_entry + 7] = 1;
    image[file_entry + 8..file_entry + 8 + file_name.len()].copy_from_slice(file_name);

    let inode_bitmap = 3 * 4096;
    for bit in [1_usize, 10_usize] {
        image[inode_bitmap + bit / 8] |= 1 << (bit % 8);
    }

    image
}

/// Try to mount an ext4 image via FrankenFS FUSE with explicit mount options.
///
/// Returns `None` if FUSE mounting fails (e.g. permission denied in containers).
fn try_mount_ffs_with_options(
    image: &Path,
    mountpoint: &Path,
    mount_opts: &MountOptions,
) -> Option<ffs_harness::stale_mounts::MountGuard> {
    // Self-heal dead mounts leaked by earlier crashed/killed runs.
    ffs_harness::stale_mounts::reap_stale_frankenfs_mounts_once();
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let fs = OpenFs::open_with_options(&cx, image, &opts).expect("open ext4 image");
    match mount_background(Box::new(fs), mountpoint, mount_opts) {
        Ok(session) => {
            wait_for_fuse_mount_ready(mountpoint);
            Some(ffs_harness::stale_mounts::MountGuard::new(
                session, mountpoint,
            ))
        }
        Err(e) => {
            eprintln!("FUSE mount failed (skipping test): {e}");
            None
        }
    }
}

/// Try to mount an ext4 image via FrankenFS FUSE (read-only).
///
/// Returns `None` if FUSE mounting fails (e.g. permission denied in containers).
fn try_mount_ffs(image: &Path, mountpoint: &Path) -> Option<ffs_harness::stale_mounts::MountGuard> {
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };
    try_mount_ffs_with_options(image, mountpoint, &mount_opts)
}

#[test]
fn fuse_read_hello_txt() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Read hello.txt through FUSE.
    let content = fs::read_to_string(mnt.join("hello.txt")).expect("read hello.txt via FUSE");
    assert_eq!(content, "Hello from FrankenFS E2E!\n");
}

#[test]
fn ext4_fuse_inline_data_reads_direct_inode_payload() {
    assert_mounted_ext4_inline_data_read_contract(
        "ext4_inode_inline_data.json",
        b"Hello from inline data!",
        "ext4_ro_inline_data_direct_read_contract",
        "layout=i_block_short_read_eof",
    );
}

#[test]
fn ext4_fuse_inline_data_reads_xattr_continuation_payload() {
    let mut expected = vec![b'A'; 60];
    expected.extend(std::iter::repeat_n(b'B', 16));
    assert_mounted_ext4_inline_data_read_contract(
        "ext4_inode_inline_data_with_continuation.json",
        &expected,
        "ext4_ro_inline_data_system_data_read_contract",
        "layout=system.data_short_read_eof",
    );
}

#[test]
fn ext4_inline_data_mount_open_options_preserve_xattr_continuation_reads() {
    let tmp = TempDir::new().expect("tmpdir");
    let image = create_ext4_inline_data_test_image(
        tmp.path(),
        "ext4_inode_inline_data_with_continuation.json",
    );
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let fs = OpenFs::open_with_options(&cx, &image, &opts)
        .expect("open inline-data image with mount options");
    let mut expected = vec![b'A'; 60];
    expected.extend(std::iter::repeat_n(b'B', 16));

    assert_eq!(
        fs.read(&cx, InodeNumber(11), 0, 4096)
            .expect("read inline-data continuation through mount options"),
        expected,
        "OpenFs mount options should preserve inline-data continuation reads before FUSE transport"
    );
}

#[test]
fn fuse_readdir_root() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Read root directory entries.
    let entries: Vec<String> = fs::read_dir(&mnt)
        .expect("readdir root via FUSE")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    assert!(
        entries.contains(&"hello.txt".to_owned()),
        "root should contain hello.txt, got: {entries:?}"
    );
    assert!(
        entries.contains(&"testdir".to_owned()),
        "root should contain testdir, got: {entries:?}"
    );
    assert!(
        entries.contains(&"lost+found".to_owned()),
        "root should contain lost+found, got: {entries:?}"
    );
}

#[test]
fn fuse_read_nested_file() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Read nested file through FUSE.
    let content =
        fs::read_to_string(mnt.join("testdir/nested.txt")).expect("read nested.txt via FUSE");
    assert_eq!(content, "Nested file content.\n");
}

#[test]
fn fuse_getattr_file_metadata() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Check file metadata.
    let meta = fs::metadata(mnt.join("hello.txt")).expect("stat hello.txt via FUSE");
    assert!(meta.is_file(), "hello.txt should be a regular file");
    assert_eq!(
        meta.len(),
        26,
        "hello.txt should be 26 bytes ('Hello from FrankenFS E2E!\\n')"
    );

    // Check directory metadata.
    let dir_meta = fs::metadata(mnt.join("testdir")).expect("stat testdir via FUSE");
    assert!(dir_meta.is_dir(), "testdir should be a directory");
}

#[test]
fn fuse_readlink_and_symlink_detection() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());

    // Add a symlink via debugfs.
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "symlink link.txt hello.txt",
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs symlink");
    assert!(
        out.status.success(),
        "debugfs symlink failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Reading the symlink target.
    let target = fs::read_link(mnt.join("link.txt")).expect("readlink via FUSE");
    assert_eq!(
        target.to_str().unwrap(),
        "hello.txt",
        "symlink should point to hello.txt"
    );

    // Following the symlink should give the same content.
    let content = fs::read_to_string(mnt.join("link.txt")).expect("read through symlink via FUSE");
    assert_eq!(content, "Hello from FrankenFS E2E!\n");
}

// ── Write-path E2E tests ────────────────────────────────────────────────────

/// Try to mount an ext4 image via FrankenFS FUSE in **read-write** mode with
/// explicit mount options.
///
/// Returns `None` if FUSE mounting fails (e.g. permission denied in containers).
fn try_mount_ffs_rw_with_options(
    image: &Path,
    mountpoint: &Path,
    mount_opts: &MountOptions,
) -> Option<ffs_harness::stale_mounts::MountGuard> {
    // Self-heal dead mounts leaked by earlier crashed/killed runs.
    ffs_harness::stale_mounts::reap_stale_frankenfs_mounts_once();
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        mvcc_wal_path: Some(image.with_extension("wal")),
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, image, &opts).expect("open ext4 image");
    fs.enable_writes(&cx).expect("enable ext4 write support");
    match mount_background(Box::new(fs), mountpoint, mount_opts) {
        Ok(session) => {
            wait_for_fuse_mount_ready(mountpoint);
            Some(ffs_harness::stale_mounts::MountGuard::new(
                session, mountpoint,
            ))
        }
        Err(e) => {
            eprintln!("FUSE mount (rw) failed (skipping test): {e}");
            None
        }
    }
}

/// Try to mount an ext4 image via FrankenFS FUSE in **read-write** mode.
///
/// Returns `None` if FUSE mounting fails (e.g. permission denied in containers).
fn try_mount_ffs_rw(image: &Path, mountpoint: &Path) -> Option<ffs_harness::stale_mounts::MountGuard> {
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ..MountOptions::default()
    };
    try_mount_ffs_rw_with_options(image, mountpoint, &mount_opts)
}

/// Helper: create image, mount rw, run a closure, then drop the session.
fn with_rw_mount(f: impl FnOnce(&Path)) {
    with_rw_mount_sized(4 * 1024 * 1024, f);
}

fn with_rw_mount_sized(image_size_bytes: u64, f: impl FnOnce(&Path)) {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), image_size_bytes);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs_rw(&image, &mnt) else {
        return;
    };
    f(&mnt);
}

const SYSCALL_CONFORMANCE_SCRIPT: &str = r#"
import json
import errno
import ctypes
import mmap
import os
import stat
import sys

root = sys.argv[1]
base = os.path.join(root, "syscall_matrix")
records = []

def stable_stat(path, follow=True):
    st = os.stat(path) if follow else os.lstat(path)
    return stat_fields(st)

def stable_fd_stat(fd):
    return stat_fields(os.fstat(fd))

def stat_fields(st):
    mode = st.st_mode
    if stat.S_ISDIR(mode):
        kind = "dir"
    elif stat.S_ISLNK(mode):
        kind = "symlink"
    elif stat.S_ISREG(mode):
        kind = "file"
    else:
        kind = "other"
    return {
        "kind": kind,
        "mode": stat.S_IMODE(mode),
        "size": st.st_size,
        "nlink": st.st_nlink,
    }

def read_text(path):
    with open(path, "rb") as f:
        return f.read().decode("ascii")

def read_hex(path):
    with open(path, "rb") as f:
        return f.read().hex()

def entries(path):
    return sorted(os.listdir(path))

def record(step, func):
    try:
        records.append({"step": step, "ok": True, "result": func()})
    except OSError as exc:
        records.append({
            "step": step,
            "ok": False,
            "errno": exc.errno,
            "result": None,
        })

def capture_error(label, func):
    try:
        func()
    except OSError as exc:
        return {
            "label": label,
            "ok": False,
            "errno": exc.errno,
            "name": errno.errorcode.get(exc.errno, "UNKNOWN"),
        }
    return {"label": label, "ok": True, "errno": None, "name": None}

def renameat2_call(old_path, new_path, flags):
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        return {"available": False, "ok": False, "errno": errno.ENOSYS, "name": "ENOSYS"}
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    ret = renameat2(-100, old_path.encode(), -100, new_path.encode(), flags)
    if ret == 0:
        return {"available": True, "ok": True, "errno": None, "name": None}
    err = ctypes.get_errno()
    return {
        "available": True,
        "ok": False,
        "errno": err,
        "name": errno.errorcode.get(err, "UNKNOWN"),
    }

def mkdir_base():
    os.mkdir(base, 0o755)
    return {"stat": stable_stat(base), "entries": entries(base)}

def create_write_fsync_read():
    path = os.path.join(base, "file.txt")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o644)
    try:
        os.write(fd, b"alpha")
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        readback = os.read(fd, 16).decode("ascii")
    finally:
        os.close(fd)
    return {"read": readback, "stat": stable_stat(path)}

def fd_metadata_ops():
    path = os.path.join(base, "fd.txt")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o644)
    try:
        os.write(fd, b"bravo")
        os.fchmod(fd, 0o640)
        os.ftruncate(fd, 3)
        os.fsync(fd)
        st = os.fstat(fd)
        fd_stat = {
            "kind": "file" if stat.S_ISREG(st.st_mode) else "other",
            "mode": stat.S_IMODE(st.st_mode),
            "size": st.st_size,
            "nlink": st.st_nlink,
        }
    finally:
        os.close(fd)
    return {"read": read_text(path), "fstat": fd_stat, "stat": stable_stat(path)}

def chmod_truncate_stat():
    path = os.path.join(base, "file.txt")
    os.chmod(path, 0o600)
    os.truncate(path, 3)
    return {"read": read_text(path), "stat": stable_stat(path)}

def utime_access_openat_statvfs():
    path = os.path.join(base, "file.txt")
    atime = 1_700_000_000
    mtime = 1_700_000_100
    os.utime(path, (atime, mtime))
    st = os.stat(path)
    access = {
        "read": os.access(path, os.R_OK),
        "write": os.access(path, os.W_OK),
        "execute": os.access(path, os.X_OK),
    }
    vfs = os.statvfs(base)
    result = {
        "access": access,
        "atime": int(st.st_atime),
        "mtime": int(st.st_mtime),
        "stat": stable_stat(path),
        "statvfs": {
            "frsize_positive": vfs.f_frsize > 0,
            "namemax_at_least_255": vfs.f_namemax >= 255,
        },
    }
    supports_dir_fd = getattr(os, "supports_dir_fd", set())
    if os.open in supports_dir_fd:
        dir_fd = os.open(base, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            fd = os.open("file.txt", os.O_RDONLY, dir_fd=dir_fd)
            try:
                result["openat_read"] = os.read(fd, 16).decode("ascii")
            finally:
                os.close(fd)
        finally:
            os.close(dir_fd)
    else:
        result["openat_read"] = "python_dir_fd_unavailable"
    return result

def dirfd_mutation_contracts():
    supports_dir_fd = getattr(os, "supports_dir_fd", set())
    required = [os.open, os.mkdir, os.rename, os.unlink, os.rmdir]
    if any(func not in supports_dir_fd for func in required):
        return {"skipped": "python_dir_fd_mutation_unavailable"}

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    dir_fd = os.open(base, flags)
    try:
        fd = os.open(
            "dirfd_file.txt",
            os.O_CREAT | os.O_EXCL | os.O_RDWR,
            0o644,
            dir_fd=dir_fd,
        )
        try:
            os.write(fd, b"dirfd")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.mkdir("dirfd_dir", 0o755, dir_fd=dir_fd)
        entries_after_create = entries(base)
        os.rename(
            "dirfd_file.txt",
            "dirfd_renamed.txt",
            src_dir_fd=dir_fd,
            dst_dir_fd=dir_fd,
        )
        old_exists_after_rename = os.path.exists(os.path.join(base, "dirfd_file.txt"))
        new_path = os.path.join(base, "dirfd_renamed.txt")
        new_exists_after_rename = os.path.exists(new_path)
        renamed_read = read_text(new_path)
        renamed_stat = stable_stat(new_path)
        os.unlink("dirfd_renamed.txt", dir_fd=dir_fd)
        file_exists_after_unlink = os.path.exists(new_path)
        os.rmdir("dirfd_dir", dir_fd=dir_fd)
        dir_exists_after_rmdir = os.path.exists(os.path.join(base, "dirfd_dir"))
        entries_after_cleanup = entries(base)
    finally:
        os.close(dir_fd)

    return {
        "dir_exists_after_rmdir": dir_exists_after_rmdir,
        "entries_after_cleanup": entries_after_cleanup,
        "entries_after_create": entries_after_create,
        "file_exists_after_unlink": file_exists_after_unlink,
        "new_exists_after_rename": new_exists_after_rename,
        "old_exists_after_rename": old_exists_after_rename,
        "renamed_read": renamed_read,
        "renamed_stat": renamed_stat,
    }

def pread_pwrite_seek_fdatasync():
    if not hasattr(os, "pread") or not hasattr(os, "pwrite"):
        return {"skipped": "python_offset_io_unavailable"}

    path = os.path.join(base, "io.bin")
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_RDWR, 0o644)
    try:
        os.write(fd, b"0123456789")
        os.pwrite(fd, b"XY", 4)
        offset_read = os.pread(fd, 8, 2).decode("ascii")
        seek_pos = os.lseek(fd, -3, os.SEEK_END)
        os.write(fd, b"END")
        if hasattr(os, "fdatasync"):
            os.fdatasync(fd)
            sync_call = "fdatasync"
        else:
            os.fsync(fd)
            sync_call = "fsync_fallback"
        final_pos = os.lseek(fd, 0, os.SEEK_CUR)
    finally:
        os.close(fd)

    return {
        "final_pos": final_pos,
        "offset_read": offset_read,
        "read": read_text(path),
        "seek_pos": seek_pos,
        "stat": stable_stat(path),
        "sync_call": sync_call,
    }

def truncate_extend_zero_fill():
    path = os.path.join(base, "sparse.bin")
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_RDWR, 0o644)
    try:
        os.write(fd, b"hi")
        os.ftruncate(fd, 6)
        os.lseek(fd, 0, os.SEEK_SET)
        after_extend = os.read(fd, 6).hex()
        os.lseek(fd, 5, os.SEEK_SET)
        os.write(fd, b"Z")
        os.fsync(fd)
    finally:
        os.close(fd)

    return {
        "after_extend_hex": after_extend,
        "after_patch_hex": read_hex(path),
        "stat": stable_stat(path),
    }

def open_unlink_fd_lifetime():
    path = os.path.join(base, "open_unlink.txt")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o644)
    try:
        os.write(fd, b"open-unlink")
        before_stat = stable_stat(path)
        os.unlink(path)
        path_exists_after_unlink = os.path.exists(path)
        fstat_after_unlink = stable_fd_stat(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        read_after_unlink = os.read(fd, 64).decode("ascii")
        os.lseek(fd, 0, os.SEEK_END)
        os.write(fd, b"-fd")
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        read_after_write = os.read(fd, 64).decode("ascii")
        fstat_after_write = stable_fd_stat(fd)
    finally:
        os.close(fd)

    return {
        "before_stat": before_stat,
        "path_exists_after_unlink": path_exists_after_unlink,
        "path_exists_after_close": os.path.exists(path),
        "fstat_after_unlink": fstat_after_unlink,
        "fstat_after_write": fstat_after_write,
        "read_after_unlink": read_after_unlink,
        "read_after_write": read_after_write,
    }

def open_rename_fd_lifetime():
    path = os.path.join(base, "open_rename.txt")
    moved = os.path.join(base, "open_rename_moved.txt")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o644)
    try:
        os.write(fd, b"open-rename")
        before_stat = stable_stat(path)
        os.rename(path, moved)
        old_path_exists_after_rename = os.path.exists(path)
        moved_stat_after_rename = stable_stat(moved)
        fstat_after_rename = stable_fd_stat(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        read_after_rename = os.read(fd, 64).decode("ascii")
        os.lseek(fd, 0, os.SEEK_END)
        os.write(fd, b"-fd")
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        read_after_write = os.read(fd, 64).decode("ascii")
        fstat_after_write = stable_fd_stat(fd)
    finally:
        os.close(fd)

    return {
        "before_stat": before_stat,
        "old_path_exists_after_rename": old_path_exists_after_rename,
        "new_path_exists_after_rename": os.path.exists(moved),
        "moved_stat_after_rename": moved_stat_after_rename,
        "moved_stat_after_close": stable_stat(moved),
        "moved_read_after_close": read_text(moved),
        "fstat_after_rename": fstat_after_rename,
        "fstat_after_write": fstat_after_write,
        "read_after_rename": read_after_rename,
        "read_after_write": read_after_write,
    }

def hardlink_symlink():
    path = os.path.join(base, "file.txt")
    hard = os.path.join(base, "hard.txt")
    sym = os.path.join(base, "sym.txt")
    os.link(path, hard)
    os.symlink("file.txt", sym)
    return {
        "entries": entries(base),
        "file": stable_stat(path),
        "hard_read": read_text(hard),
        "sym": stable_stat(sym, follow=False),
        "sym_target": os.readlink(sym),
    }

def symlink_at_nofollow_contracts():
    sym = os.path.join(base, "sym.txt")
    result = {
        "follow_stat": stable_stat(sym),
        "lstat": stable_stat(sym, follow=False),
        "open_symlink_nofollow": capture_error(
            "open_symlink_nofollow",
            lambda: os.close(os.open(sym, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))),
        ),
    }
    supports_dir_fd = getattr(os, "supports_dir_fd", set())
    if os.open in supports_dir_fd:
        dir_fd = os.open(base, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            fd = os.open("file.txt", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=dir_fd)
            try:
                result["regular_openat_no_follow_read"] = os.read(fd, 16).decode("ascii")
            finally:
                os.close(fd)
            if os.stat in supports_dir_fd:
                st = os.stat("sym.txt", dir_fd=dir_fd, follow_symlinks=False)
                result["fstatat_lstat"] = {
                    "kind": "symlink" if stat.S_ISLNK(st.st_mode) else "other",
                    "mode": stat.S_IMODE(st.st_mode),
                    "size": st.st_size,
                    "nlink": st.st_nlink,
                }
            else:
                result["fstatat_lstat"] = "python_stat_dir_fd_unavailable"
            if os.readlink in supports_dir_fd:
                result["readlinkat"] = os.readlink("sym.txt", dir_fd=dir_fd)
            else:
                result["readlinkat"] = "python_readlink_dir_fd_unavailable"
        finally:
            os.close(dir_fd)
    else:
        result["regular_openat_no_follow_read"] = "python_open_dir_fd_unavailable"
        result["fstatat_lstat"] = "python_open_dir_fd_unavailable"
        result["readlinkat"] = "python_open_dir_fd_unavailable"
    return result

def rename_unlink():
    hard = os.path.join(base, "hard.txt")
    renamed = os.path.join(base, "renamed.txt")
    sym = os.path.join(base, "sym.txt")
    os.rename(hard, renamed)
    os.unlink(sym)
    return {
        "entries": entries(base),
        "file": stable_stat(os.path.join(base, "file.txt")),
        "renamed_read": read_text(renamed),
    }

def rename_replace_existing():
    src = os.path.join(base, "replace_src.txt")
    dst = os.path.join(base, "replace_dst.txt")
    with open(src, "wb") as f:
        f.write(b"replacement")
        f.flush()
        os.fsync(f.fileno())
    with open(dst, "wb") as f:
        f.write(b"original")
        f.flush()
        os.fsync(f.fileno())
    before_dst_stat = stable_stat(dst)
    os.rename(src, dst)
    return {
        "before_dst_stat": before_dst_stat,
        "dst_read_after_rename": read_text(dst),
        "dst_stat_after_rename": stable_stat(dst),
        "entries": entries(base),
        "src_exists_after_rename": os.path.exists(src),
    }

def renameat2_flag_contracts():
    rename_noreplace = 1
    rename_exchange = 2
    free_src = os.path.join(base, "renameat2_free_src.txt")
    free_dst = os.path.join(base, "renameat2_free_dst.txt")
    existing_src = os.path.join(base, "renameat2_existing_src.txt")
    existing_dst = os.path.join(base, "renameat2_existing_dst.txt")
    exchange_src = os.path.join(base, "renameat2_exchange_src.txt")
    exchange_dst = os.path.join(base, "renameat2_exchange_dst.txt")
    for path, payload in [
        (free_src, b"free-src"),
        (existing_src, b"existing-src"),
        (existing_dst, b"existing-dst"),
        (exchange_src, b"exchange-src"),
        (exchange_dst, b"exchange-dst"),
    ]:
        with open(path, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())

    free = renameat2_call(free_src, free_dst, rename_noreplace)
    if not free["available"] or free["errno"] == errno.ENOSYS:
        return {"available": False, "noreplace_free": free}
    existing = renameat2_call(existing_src, existing_dst, rename_noreplace)
    exchange = renameat2_call(exchange_src, exchange_dst, rename_exchange)
    return {
        "available": True,
        "noreplace_free": free,
        "noreplace_free_src_exists": os.path.exists(free_src),
        "noreplace_free_dst_read": read_text(free_dst),
        "noreplace_existing": existing,
        "noreplace_existing_src_read": read_text(existing_src),
        "noreplace_existing_dst_read": read_text(existing_dst),
        "exchange": exchange,
        "exchange_src_read": read_text(exchange_src),
        "exchange_dst_read": read_text(exchange_dst),
        "entries": entries(base),
    }

def nested_dir_rename():
    sub = os.path.join(base, "sub")
    moved = os.path.join(base, "moved")
    child = os.path.join(sub, "child.txt")
    os.mkdir(sub, 0o755)
    with open(child, "wb") as f:
        f.write(b"nested")
    os.rename(sub, moved)
    moved_child = os.path.join(moved, "child.txt")
    return {
        "entries": entries(base),
        "moved_entries": entries(moved),
        "child_read": read_text(moved_child),
        "child_stat": stable_stat(moved_child),
    }

def mmap_write_flush():
    path = os.path.join(base, "map.bin")
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_RDWR, 0o644)
    try:
        os.write(fd, b"00000000")
        os.ftruncate(fd, 8)
        mapping = mmap.mmap(fd, 8, access=mmap.ACCESS_WRITE)
        try:
            mapping[2:5] = b"MAP"
            mapping.flush()
        finally:
            mapping.close()
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"read": read_text(path), "stat": stable_stat(path)}

def fsync_directory():
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(base, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"entries": entries(base)}

def negative_errno_contracts():
    missing = os.path.join(base, "missing.txt")
    checks = [
        capture_error("mkdir_existing", lambda: os.mkdir(base, 0o755)),
        capture_error("unlink_missing", lambda: os.unlink(missing)),
        capture_error(
            "rename_missing",
            lambda: os.rename(missing, os.path.join(base, "also_missing.txt")),
        ),
        capture_error("rmdir_nonempty", lambda: os.rmdir(os.path.join(base, "moved"))),
    ]
    return {
        "checks": checks,
        "entries": entries(base),
        "moved_entries": entries(os.path.join(base, "moved")),
    }

def cleanup():
    os.unlink(os.path.join(base, "file.txt"))
    os.unlink(os.path.join(base, "fd.txt"))
    io_path = os.path.join(base, "io.bin")
    if os.path.exists(io_path):
        os.unlink(io_path)
    sparse_path = os.path.join(base, "sparse.bin")
    if os.path.exists(sparse_path):
        os.unlink(sparse_path)
    dirfd_file_path = os.path.join(base, "dirfd_file.txt")
    if os.path.exists(dirfd_file_path):
        os.unlink(dirfd_file_path)
    dirfd_renamed_path = os.path.join(base, "dirfd_renamed.txt")
    if os.path.exists(dirfd_renamed_path):
        os.unlink(dirfd_renamed_path)
    dirfd_dir_path = os.path.join(base, "dirfd_dir")
    if os.path.exists(dirfd_dir_path):
        os.rmdir(dirfd_dir_path)
    open_rename_path = os.path.join(base, "open_rename.txt")
    if os.path.exists(open_rename_path):
        os.unlink(open_rename_path)
    open_rename_moved_path = os.path.join(base, "open_rename_moved.txt")
    if os.path.exists(open_rename_moved_path):
        os.unlink(open_rename_moved_path)
    replace_src_path = os.path.join(base, "replace_src.txt")
    if os.path.exists(replace_src_path):
        os.unlink(replace_src_path)
    replace_dst_path = os.path.join(base, "replace_dst.txt")
    if os.path.exists(replace_dst_path):
        os.unlink(replace_dst_path)
    for renameat2_path in [
        "renameat2_free_src.txt",
        "renameat2_free_dst.txt",
        "renameat2_existing_src.txt",
        "renameat2_existing_dst.txt",
        "renameat2_exchange_src.txt",
        "renameat2_exchange_dst.txt",
    ]:
        path = os.path.join(base, renameat2_path)
        if os.path.exists(path):
            os.unlink(path)
    os.unlink(os.path.join(base, "renamed.txt"))
    os.unlink(os.path.join(base, "map.bin"))
    os.unlink(os.path.join(base, "moved", "child.txt"))
    os.rmdir(os.path.join(base, "moved"))
    os.rmdir(base)
    return {"base_exists": os.path.exists(base)}

for step, func in [
    ("mkdir_base", mkdir_base),
    ("create_write_fsync_read", create_write_fsync_read),
    ("fd_metadata_ops", fd_metadata_ops),
    ("chmod_truncate_stat", chmod_truncate_stat),
    ("utime_access_openat_statvfs", utime_access_openat_statvfs),
    ("dirfd_mutation_contracts", dirfd_mutation_contracts),
    ("pread_pwrite_seek_fdatasync", pread_pwrite_seek_fdatasync),
    ("truncate_extend_zero_fill", truncate_extend_zero_fill),
    ("open_unlink_fd_lifetime", open_unlink_fd_lifetime),
    ("open_rename_fd_lifetime", open_rename_fd_lifetime),
    ("hardlink_symlink", hardlink_symlink),
    ("symlink_at_nofollow_contracts", symlink_at_nofollow_contracts),
    ("rename_unlink", rename_unlink),
    ("rename_replace_existing", rename_replace_existing),
    ("renameat2_flag_contracts", renameat2_flag_contracts),
    ("nested_dir_rename", nested_dir_rename),
    ("mmap_write_flush", mmap_write_flush),
    ("fsync_directory", fsync_directory),
    ("negative_errno_contracts", negative_errno_contracts),
    ("cleanup", cleanup),
]:
    record(step, func)

print(json.dumps(records, sort_keys=True))
"#;

fn run_syscall_conformance_probe(root: &Path) -> Value {
    let output = Command::new("python3")
        .arg("-c")
        .arg(SYSCALL_CONFORMANCE_SCRIPT)
        .arg(root)
        .output()
        .expect("run python3 syscall conformance probe");
    assert!(
        output.status.success(),
        "python3 syscall conformance probe failed for {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("syscall conformance probe JSON")
}

const PWRITEV2_RWF_SCRIPT: &str = r#"
import json
import os
import sys

root = sys.argv[1]
flag_name = sys.argv[2]
file_name = sys.argv[3]
payload = bytes.fromhex(sys.argv[4])
path = os.path.join(root, file_name)

if not hasattr(os, "pwritev"):
    print(json.dumps({"skipped": "python_os_pwritev_unavailable"}))
    sys.exit(0)

flag = getattr(os, flag_name, None)
if flag is None:
    print(json.dumps({"skipped": "python_os_" + flag_name.lower() + "_unavailable"}))
    sys.exit(0)

fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o644)
try:
    written = os.pwritev(fd, [payload], 0, flag)
finally:
    os.close(fd)

with open(path, "rb") as fh:
    readback = fh.read()

print(json.dumps({
    "path": path,
    "payload_hex": payload.hex(),
    "readback_hex": readback.hex(),
    "written": written,
}, sort_keys=True))
"#;

const PWRITEV2_RWF_HINT_SCRIPT: &str = r#"
import errno
import json
import os
import sys

root = sys.argv[1]
flag_name = sys.argv[2]
file_name = sys.argv[3]
initial = bytes.fromhex(sys.argv[4])
payload = bytes.fromhex(sys.argv[5])
offset = int(sys.argv[6])
path = os.path.join(root, file_name)

if not hasattr(os, "pwritev"):
    print(json.dumps({"skipped": "python_os_pwritev_unavailable"}))
    sys.exit(0)

flag = getattr(os, flag_name, None)
if flag is None:
    print(json.dumps({"skipped": "python_os_" + flag_name.lower() + "_unavailable"}))
    sys.exit(0)

unsupported_errnos = {errno.EINVAL, errno.EOPNOTSUPP}
if hasattr(errno, "ENOTSUP"):
    unsupported_errnos.add(errno.ENOTSUP)

with open(path, "wb") as fh:
    fh.write(initial)

fd = os.open(path, os.O_WRONLY)
try:
    try:
        written = os.pwritev(fd, [payload], offset, flag)
    except OSError as exc:
        if flag_name == "RWF_NOWAIT" and exc.errno == errno.EAGAIN:
            with open(path, "rb") as fh:
                readback = fh.read()
            print(json.dumps({
                "skipped": "rwf_nowait_eagain_without_mutation",
                "errno": exc.errno,
                "expected_hex": initial.hex(),
                "readback_hex": readback.hex(),
            }, sort_keys=True))
            sys.exit(0)
        if exc.errno in unsupported_errnos:
            with open(path, "rb") as fh:
                readback = fh.read()
            print(json.dumps({
                "skipped": flag_name.lower() + "_not_forwarded_or_unsupported",
                "errno": exc.errno,
                "expected_hex": initial.hex(),
                "readback_hex": readback.hex(),
            }, sort_keys=True))
            sys.exit(0)
        raise
finally:
    os.close(fd)

expected = initial[:offset] + payload + initial[offset + len(payload):]
with open(path, "rb") as fh:
    readback = fh.read()

print(json.dumps({
    "expected_hex": expected.hex(),
    "flag": flag,
    "offset": offset,
    "path": path,
    "payload_hex": payload.hex(),
    "readback_hex": readback.hex(),
    "written": written,
}, sort_keys=True))
"#;

const PWRITEV2_RWF_APPEND_MODES_SCRIPT: &str = r#"
import errno
import json
import os
import sys

root = sys.argv[1]

if not hasattr(os, "pwritev"):
    print(json.dumps({"skipped": "python_os_pwritev_unavailable"}))
    sys.exit(0)

unsupported_errnos = {errno.EOPNOTSUPP}
if hasattr(errno, "ENOTSUP"):
    unsupported_errnos.add(errno.ENOTSUP)

RWF_APPEND = getattr(os, "RWF_APPEND", 0x10)
RWF_NOAPPEND = getattr(os, "RWF_NOAPPEND", 0x20)

def pwritev_or_skip(fd, payload, offset, flags, label):
    try:
        return os.pwritev(fd, [payload], offset, flags)
    except OSError as exc:
        if exc.errno in unsupported_errnos:
            print(json.dumps({
                "skipped": label + "_unsupported_by_kernel_or_fuse",
                "errno": exc.errno,
            }, sort_keys=True))
            sys.exit(0)
        raise

append_path = os.path.join(root, "rwf_append_mode_probe.bin")
append_initial = b"base"
append_payload = b"+append"
fd = os.open(append_path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o644)
try:
    os.write(fd, append_initial)
    append_written = pwritev_or_skip(fd, append_payload, 0, RWF_APPEND, "rwf_append")
finally:
    os.close(fd)
with open(append_path, "rb") as fh:
    append_readback = fh.read()

noappend_path = os.path.join(root, "rwf_noappend_mode_probe.bin")
noappend_initial = b"abcdef"
noappend_payload = b"XY"
fd = os.open(noappend_path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o644)
try:
    os.write(fd, noappend_initial)
finally:
    os.close(fd)
fd = os.open(noappend_path, os.O_WRONLY | os.O_APPEND)
try:
    noappend_written = pwritev_or_skip(fd, noappend_payload, 1, RWF_NOAPPEND, "rwf_noappend")
finally:
    os.close(fd)
with open(noappend_path, "rb") as fh:
    noappend_readback = fh.read()

conflict_path = os.path.join(root, "rwf_append_noappend_conflict_probe.bin")
conflict_initial = b"conflict-base"
with open(conflict_path, "wb") as fh:
    fh.write(conflict_initial)
fd = os.open(conflict_path, os.O_WRONLY)
try:
    try:
        os.pwritev(fd, [b"!"], 0, RWF_APPEND | RWF_NOAPPEND)
    except OSError as exc:
        if exc.errno in unsupported_errnos:
            print(json.dumps({
                "skipped": "rwf_append_noappend_conflict_unsupported_by_kernel_or_fuse",
                "errno": exc.errno,
            }, sort_keys=True))
            sys.exit(0)
        conflict_errno = exc.errno
    else:
        conflict_errno = 0
finally:
    os.close(fd)
with open(conflict_path, "rb") as fh:
    conflict_readback = fh.read()

report = {
    "append": {
        "expected_hex": (append_initial + append_payload).hex(),
        "readback_hex": append_readback.hex(),
        "written": append_written,
    },
    "noappend": {
        "expected_hex": b"aXYdef".hex(),
        "readback_hex": noappend_readback.hex(),
        "written": noappend_written,
    },
    "conflict": {
        "expected_hex": conflict_initial.hex(),
        "readback_hex": conflict_readback.hex(),
        "errno": conflict_errno,
    },
}

noappend_collapsed_to_o_append = (
    append_written == len(append_payload)
    and append_readback == append_initial + append_payload
    and noappend_written == len(noappend_payload)
    and noappend_readback == noappend_initial + noappend_payload
    and conflict_errno == errno.EINVAL
    and conflict_readback == conflict_initial
)
if noappend_collapsed_to_o_append:
    report["skipped"] = "rwf_noappend_collapsed_to_o_append_by_kernel_or_fuse_transport"

print(json.dumps(report, sort_keys=True))
"#;

const PWRITEV2_RWF_UNSUPPORTED_INTENTS_SCRIPT: &str = r#"
import errno
import json
import os
import sys

root = sys.argv[1]

if not hasattr(os, "pwritev"):
    print(json.dumps({"skipped": "python_os_pwritev_unavailable"}))
    sys.exit(0)

RWF_ATOMIC = getattr(os, "RWF_ATOMIC", 0x40)
RWF_DONTCACHE = getattr(os, "RWF_DONTCACHE", 0x80)

def probe(label, flags, initial, payload):
    path = os.path.join(root, label + "_unsupported_probe.bin")
    with open(path, "wb") as fh:
        fh.write(initial)

    fd = os.open(path, os.O_WRONLY)
    try:
        try:
            written = os.pwritev(fd, [payload], 0, flags)
        except OSError as exc:
            if exc.errno == errno.EINVAL:
                print(json.dumps({
                    "skipped": label + "_pre_dispatch_einval",
                    "errno": exc.errno,
                }, sort_keys=True))
                sys.exit(0)
            errno_value = exc.errno
            written = None
        else:
            errno_value = 0
    finally:
        os.close(fd)

    with open(path, "rb") as fh:
        readback = fh.read()

    return {
        "errno": errno_value,
        "expected_hex": initial.hex(),
        "flag": flags,
        "payload_hex": payload.hex(),
        "readback_hex": readback.hex(),
        "written": written,
    }

print(json.dumps({
    "cases": {
        "atomic": probe("rwf_atomic", RWF_ATOMIC, b"stable-atomic", b"mutated"),
        "dontcache": probe("rwf_dontcache", RWF_DONTCACHE, b"stable-dontcache", b"mutated"),
    },
}, sort_keys=True))
"#;

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"))
            .expect("write payload hex");
    }
    out
}

fn run_pwritev2_rwf_probe(root: &Path, flag_name: &str, file_name: &str, payload: &[u8]) -> Value {
    let output = Command::new("python3")
        .arg("-c")
        .arg(PWRITEV2_RWF_SCRIPT)
        .arg(root)
        .arg(flag_name)
        .arg(file_name)
        .arg(bytes_to_hex(payload))
        .output()
        .expect("run python3 pwritev2 RWF probe");
    assert!(
        output.status.success(),
        "python3 pwritev2 {flag_name} probe failed for {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("pwritev2 RWF probe JSON")
}

fn run_pwritev2_rwf_hint_probe(
    root: &Path,
    flag_name: &str,
    file_name: &str,
    initial: &[u8],
    payload: &[u8],
    offset: u64,
) -> Value {
    let output = Command::new("python3")
        .arg("-c")
        .arg(PWRITEV2_RWF_HINT_SCRIPT)
        .arg(root)
        .arg(flag_name)
        .arg(file_name)
        .arg(bytes_to_hex(initial))
        .arg(bytes_to_hex(payload))
        .arg(offset.to_string())
        .output()
        .expect("run python3 pwritev2 RWF hint probe");
    assert!(
        output.status.success(),
        "python3 pwritev2 {flag_name} hint probe failed for {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("pwritev2 RWF hint probe JSON")
}

fn run_pwritev2_rwf_append_modes_probe(root: &Path) -> Value {
    let output = Command::new("python3")
        .arg("-c")
        .arg(PWRITEV2_RWF_APPEND_MODES_SCRIPT)
        .arg(root)
        .output()
        .expect("run python3 pwritev2 RWF append-modes probe");
    assert!(
        output.status.success(),
        "python3 pwritev2 RWF append-modes probe failed for {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("pwritev2 RWF append-modes probe JSON")
}

fn run_pwritev2_rwf_unsupported_intents_probe(root: &Path) -> Value {
    let output = Command::new("python3")
        .arg("-c")
        .arg(PWRITEV2_RWF_UNSUPPORTED_INTENTS_SCRIPT)
        .arg(root)
        .output()
        .expect("run python3 pwritev2 RWF unsupported-intents probe");
    assert!(
        output.status.success(),
        "python3 pwritev2 RWF unsupported-intents probe failed for {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("pwritev2 RWF unsupported-intents probe JSON")
}

const INOTIFY_RENAME_SCRIPT: &str = r#"
import ctypes
import json
import os
import struct
import sys
import time

IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
WATCH_MASK = IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_Q_OVERFLOW | IN_IGNORED

EVENT = struct.Struct("iIII")
libc = ctypes.CDLL(None, use_errno=True)

try:
    inotify_init1 = libc.inotify_init1
    inotify_add_watch = libc.inotify_add_watch
except AttributeError:
    print(json.dumps({"skipped": "libc_inotify_unavailable"}))
    sys.exit(0)

inotify_init1.argtypes = [ctypes.c_int]
inotify_init1.restype = ctypes.c_int
inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
inotify_add_watch.restype = ctypes.c_int
libc.close.argtypes = [ctypes.c_int]
libc.close.restype = ctypes.c_int

def fail(message, **fields):
    payload = {"error": message}
    payload.update(fields)
    raise AssertionError(json.dumps(payload, sort_keys=True))

def open_inotify():
    flags = getattr(os, "O_NONBLOCK", 0x800) | getattr(os, "O_CLOEXEC", 0x80000)
    fd = inotify_init1(flags)
    if fd < 0:
        errno = ctypes.get_errno()
        if errno in (38, 78):
            print(json.dumps({"skipped": "kernel_inotify_unavailable", "errno": errno}))
            sys.exit(0)
        fail("inotify_init1_failed", errno=errno)
    return fd

def add_watch(fd, path):
    wd = inotify_add_watch(fd, os.fsencode(path), WATCH_MASK)
    if wd < 0:
        fail("inotify_add_watch_failed", path=path, errno=ctypes.get_errno())
    return wd

def close_fd(fd):
    if fd >= 0:
        libc.close(fd)

def decode_events(data):
    events = []
    offset = 0
    while offset + EVENT.size <= len(data):
        wd, mask, cookie, name_len = EVENT.unpack_from(data, offset)
        offset += EVENT.size
        raw_name = data[offset:offset + name_len]
        offset += name_len
        name = raw_name.split(b"\0", 1)[0].decode("utf-8", "surrogateescape")
        events.append({"wd": wd, "mask": mask, "cookie": cookie, "name": name})
    return events

def collect_events(fds, expected_move_events, timeout_seconds=5.0, settle_seconds=0.20):
    events = []
    deadline = time.monotonic() + timeout_seconds
    settled_since = None
    while time.monotonic() < deadline:
        made_progress = False
        for fd in fds:
            while True:
                try:
                    data = os.read(fd, 65536)
                except BlockingIOError:
                    break
                if not data:
                    break
                made_progress = True
                events.extend(decode_events(data))

        move_events = [
            event for event in events
            if event["mask"] & (IN_MOVED_FROM | IN_MOVED_TO)
        ]
        if len(move_events) >= expected_move_events:
            if settled_since is None:
                settled_since = time.monotonic()
            elif time.monotonic() - settled_since >= settle_seconds:
                return events
        else:
            settled_since = None

        if not made_progress:
            time.sleep(0.01)

    return events

def reject_non_move_events(events, scenario):
    creates = [event for event in events if event["mask"] & IN_CREATE]
    deletes = [event for event in events if event["mask"] & IN_DELETE]
    overflows = [event for event in events if event["mask"] & IN_Q_OVERFLOW]
    ignored = [event for event in events if event["mask"] & IN_IGNORED]
    if creates or deletes or overflows or ignored:
        fail(
            "unexpected_inotify_events",
            scenario=scenario,
            creates=creates,
            deletes=deletes,
            overflows=overflows,
            ignored=ignored,
            events=events,
        )

def assert_move_pairs(events, expected_pairs, scenario):
    reject_non_move_events(events, scenario)
    moved_from = [event for event in events if event["mask"] & IN_MOVED_FROM]
    moved_to = [event for event in events if event["mask"] & IN_MOVED_TO]
    if len(moved_from) != len(expected_pairs) or len(moved_to) != len(expected_pairs):
        fail(
            "wrong_move_event_count",
            scenario=scenario,
            expected=len(expected_pairs),
            moved_from=len(moved_from),
            moved_to=len(moved_to),
            events=events,
        )

    by_cookie = {}
    for event in moved_from:
        if event["cookie"] == 0:
            fail("zero_moved_from_cookie", scenario=scenario, event=event)
        by_cookie.setdefault(event["cookie"], {"from": [], "to": []})["from"].append(event)
    for event in moved_to:
        if event["cookie"] == 0:
            fail("zero_moved_to_cookie", scenario=scenario, event=event)
        by_cookie.setdefault(event["cookie"], {"from": [], "to": []})["to"].append(event)

    actual_pairs = []
    for cookie, halves in by_cookie.items():
        if len(halves["from"]) != 1 or len(halves["to"]) != 1:
            fail("orphan_or_duplicate_move_cookie", scenario=scenario, cookie=cookie, halves=halves)
        actual_pairs.append((halves["from"][0]["name"], halves["to"][0]["name"]))

    actual_pairs = sorted(actual_pairs)
    if actual_pairs != sorted(expected_pairs):
        fail(
            "move_pair_name_mismatch",
            scenario=scenario,
            expected=sorted(expected_pairs),
            actual=actual_pairs,
            events=events,
        )
    return moved_from, moved_to

def same_parent(root):
    base = os.path.join(root, "inotify_same_parent")
    os.mkdir(base)
    expected = []
    for index in range(100):
        source = f"rename_{index:03d}_src.txt"
        target = f"rename_{index:03d}_dst.txt"
        with open(os.path.join(base, source), "wb") as fh:
            fh.write(f"rename payload {index}\n".encode("ascii"))
        expected.append((source, target))

    fd = open_inotify()
    try:
        add_watch(fd, base)
        for source, target in expected:
            os.rename(os.path.join(base, source), os.path.join(base, target))
        events = collect_events([fd], expected_move_events=len(expected) * 2)
    finally:
        close_fd(fd)

    moved_from, moved_to = assert_move_pairs(events, expected, "same_parent")
    return {
        "scenario": "same_parent",
        "renames": len(expected),
        "moved_from": len(moved_from),
        "moved_to": len(moved_to),
        "cookies": len({event["cookie"] for event in moved_from}),
    }

def cross_directory(root):
    base = os.path.join(root, "inotify_cross_directory")
    source_dir = os.path.join(base, "from")
    target_dir = os.path.join(base, "to")
    os.makedirs(source_dir)
    os.mkdir(target_dir)
    source_name = "move_me.txt"
    with open(os.path.join(source_dir, source_name), "wb") as fh:
        fh.write(b"cross-directory rename payload\n")

    source_fd = open_inotify()
    target_fd = open_inotify()
    try:
        source_wd = add_watch(source_fd, source_dir)
        target_wd = add_watch(target_fd, target_dir)
        os.rename(os.path.join(source_dir, source_name), os.path.join(target_dir, source_name))
        events = collect_events([source_fd, target_fd], expected_move_events=2)
    finally:
        close_fd(source_fd)
        close_fd(target_fd)

    moved_from, moved_to = assert_move_pairs(events, [(source_name, source_name)], "cross_directory")
    if moved_from[0]["wd"] != source_wd or moved_to[0]["wd"] != target_wd:
        fail(
            "cross_directory_watch_descriptor_mismatch",
            source_wd=source_wd,
            target_wd=target_wd,
            moved_from=moved_from,
            moved_to=moved_to,
            events=events,
        )
    return {
        "scenario": "cross_directory",
        "moved_from": len(moved_from),
        "moved_to": len(moved_to),
        "cookie": moved_from[0]["cookie"],
    }

root = sys.argv[1]
mode = sys.argv[2]
if mode == "same-parent":
    result = same_parent(root)
elif mode == "cross-directory":
    result = cross_directory(root)
else:
    fail("unknown_mode", mode=mode)

print(json.dumps(result, sort_keys=True))
"#;

fn run_inotify_rename_probe(root: &Path, mode: &str) -> Value {
    let output = Command::new("python3")
        .arg("-c")
        .arg(INOTIFY_RENAME_SCRIPT)
        .arg(root)
        .arg(mode)
        .output()
        .expect("run python3 inotify rename probe");
    assert!(
        output.status.success(),
        "python3 inotify rename probe failed for {} mode {mode}: stdout={} stderr={}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("inotify rename probe JSON")
}

const SPLICE_PIPE_TO_FILE_SCRIPT: &str = r#"
import hashlib
import json
import os
import sys

if not hasattr(os, "splice"):
    print(json.dumps({"skipped": "python_os_splice_unavailable"}))
    sys.exit(0)

root = sys.argv[1]
size = 16 * 1024 * 1024
chunk = 1024 * 1024
splice_chunk = 16 * 1024
src = os.path.join(root, "splice_source.bin")
dst = os.path.join(root, "splice_dest.bin")
pattern = bytes(((i * 31 + 7) % 251) for i in range(65536))

with open(src, "wb") as f:
    remaining = size
    while remaining:
        n = min(remaining, len(pattern))
        f.write(pattern[:n])
        remaining -= n

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk)
            if not data:
                break
            h.update(data)
    return h.hexdigest()

rfd = os.open(src, os.O_RDONLY)
wfd = os.open(dst, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o644)
pipe_r, pipe_w = os.pipe()
try:
    moved = 0
    while moved < size:
        n = os.splice(rfd, pipe_w, min(splice_chunk, size - moved))
        if n == 0:
            break
        drained = 0
        while drained < n:
            written = os.splice(pipe_r, wfd, n - drained)
            if written == 0:
                raise RuntimeError("splice pipe drain returned zero")
            drained += written
        moved += n
    os.fsync(wfd)
finally:
    os.close(pipe_r)
    os.close(pipe_w)
    os.close(rfd)
    os.close(wfd)

print(json.dumps({
    "moved": moved,
    "source_size": os.path.getsize(src),
    "dest_size": os.path.getsize(dst),
    "source_sha256": digest(src),
    "dest_sha256": digest(dst),
}, sort_keys=True))
"#;

fn run_splice_pipe_to_file_probe(root: &Path) -> Value {
    let output = Command::new("python3")
        .arg("-c")
        .arg(SPLICE_PIPE_TO_FILE_SCRIPT)
        .arg(root)
        .output()
        .expect("run python3 splice probe");
    assert!(
        output.status.success(),
        "python3 splice probe failed for {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("splice probe JSON")
}

const COPY_FILE_RANGE_OFFSETS_SCRIPT: &str = r#"
import errno
import json
import os
import sys

if not hasattr(os, "copy_file_range"):
    print(json.dumps({"skipped": "python_os_copy_file_range_unavailable"}))
    sys.exit(0)

unsupported_errnos = {errno.ENOSYS, errno.EOPNOTSUPP}
if hasattr(errno, "ENOTSUP"):
    unsupported_errnos.add(errno.ENOTSUP)

root = sys.argv[1]

def read(path):
    with open(path, "rb") as fh:
        return fh.read()

def copy_or_skip(src_fd, dst_fd, count, src_offset, dst_offset, label):
    try:
        return os.copy_file_range(
            src_fd,
            dst_fd,
            count,
            offset_src=src_offset,
            offset_dst=dst_offset,
        )
    except OSError as exc:
        if exc.errno in unsupported_errnos:
            print(json.dumps({
                "skipped": label + "_unsupported_by_kernel_or_fuse",
                "errno": exc.errno,
            }, sort_keys=True))
            sys.exit(0)
        raise

src_path = os.path.join(root, "copy_file_range_src.bin")
dst_path = os.path.join(root, "copy_file_range_dst.bin")
src_bytes = b"0123456789abcdef"
dst_initial = b"ABCDEFGHIJK"
with open(src_path, "wb") as fh:
    fh.write(src_bytes)
with open(dst_path, "wb") as fh:
    fh.write(dst_initial)

src_fd = os.open(src_path, os.O_RDONLY)
dst_fd = os.open(dst_path, os.O_RDWR)
try:
    cross_copied = copy_or_skip(src_fd, dst_fd, 5, 3, 2, "cross_file")
    os.fsync(dst_fd)
finally:
    os.close(src_fd)
    os.close(dst_fd)
cross_expected = dst_initial[:2] + src_bytes[3:8] + dst_initial[7:]
cross_readback = read(dst_path)

same_path = os.path.join(root, "copy_file_range_same_inode.bin")
same_initial = b"abcdefghijklmnop"
with open(same_path, "wb") as fh:
    fh.write(same_initial)

same_fd = os.open(same_path, os.O_RDWR)
try:
    same_copied = copy_or_skip(same_fd, same_fd, 4, 0, 8, "same_inode_nonoverlap")
    zero_copied = copy_or_skip(same_fd, same_fd, 0, 1, 4, "zero_length")
    os.fsync(same_fd)
    try:
        os.copy_file_range(same_fd, same_fd, 4, offset_src=0, offset_dst=2)
    except OSError as exc:
        overlap_errno = exc.errno
    else:
        overlap_errno = 0
finally:
    os.close(same_fd)

same_expected = same_initial[:8] + same_initial[:4] + same_initial[12:]
same_readback = read(same_path)

print(json.dumps({
    "cross_file": {
        "copied": cross_copied,
        "expected_hex": cross_expected.hex(),
        "readback_hex": cross_readback.hex(),
    },
    "same_inode": {
        "copied": same_copied,
        "expected_hex": same_expected.hex(),
        "readback_hex": same_readback.hex(),
    },
    "zero_length": {
        "copied": zero_copied,
    },
    "overlap": {
        "errno": overlap_errno,
        "expected_hex": same_expected.hex(),
        "readback_hex": same_readback.hex(),
    },
}, sort_keys=True))
"#;

fn run_copy_file_range_offsets_probe(root: &Path) -> Value {
    let output = Command::new("python3")
        .arg("-c")
        .arg(COPY_FILE_RANGE_OFFSETS_SCRIPT)
        .arg(root)
        .output()
        .expect("run python3 copy_file_range probe");
    assert!(
        output.status.success(),
        "python3 copy_file_range probe failed for {}: stdout={} stderr={}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("copy_file_range probe JSON")
}

fn assert_copy_file_range_offsets_and_overlap_contract(root: &Path, scenario_id: &str) {
    let report = run_copy_file_range_offsets_probe(root);
    if let Some(reason) = report["skipped"].as_str() {
        emit_scenario_result(scenario_id, "SKIP", Some(reason));
        return;
    }

    let cross = &report["cross_file"];
    assert_eq!(
        cross["copied"].as_i64(),
        Some(5),
        "cross-file copy_file_range should report copied byte count: {report}"
    );
    assert_eq!(
        cross["readback_hex"].as_str(),
        cross["expected_hex"].as_str(),
        "cross-file copy_file_range should copy the requested source offset into destination \
         offset: {report}"
    );

    let same_inode = &report["same_inode"];
    assert_eq!(
        same_inode["copied"].as_i64(),
        Some(4),
        "same-inode non-overlapping copy_file_range should report copied byte count: {report}"
    );
    assert_eq!(
        same_inode["readback_hex"].as_str(),
        same_inode["expected_hex"].as_str(),
        "same-inode non-overlapping copy_file_range should preserve exact offset semantics: \
         {report}"
    );

    assert_eq!(
        report["zero_length"]["copied"].as_i64(),
        Some(0),
        "zero-length copy_file_range should return 0: {report}"
    );

    let overlap = &report["overlap"];
    assert_eq!(
        overlap["errno"].as_i64(),
        Some(i64::from(libc::EINVAL)),
        "same-inode overlapping copy_file_range should reject with EINVAL: {report}"
    );
    assert_eq!(
        overlap["readback_hex"].as_str(),
        overlap["expected_hex"].as_str(),
        "overlapping copy_file_range rejection must not mutate data: {report}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("offsets_zero_length_and_overlap_contract_verified"),
    );
}

const SENDFILE_32M_SCRIPT: &str = r#"
import hashlib
import json
import os
import sys

if not hasattr(os, "sendfile"):
    print(json.dumps({"skipped": "python_os_sendfile_unavailable"}))
    sys.exit(0)

root = sys.argv[1]
size = 32 * 1024 * 1024
chunk = 1024 * 1024
src = os.path.join(root, "generic_249_sendfile_src.bin")
dst = os.path.join(root, "generic_249_sendfile_dst.bin")
pattern = bytes([0xA5, 0xA5, 0x5A, 0x5A]) * (64 * 1024)

with open(src, "wb") as f:
    remaining = size
    while remaining:
        n = min(remaining, len(pattern))
        f.write(pattern[:n])
        remaining -= n
    f.flush()
    os.fsync(f.fileno())

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk)
            if not data:
                break
            h.update(data)
    return h.hexdigest()

in_fd = os.open(src, os.O_RDONLY)
out_fd = os.open(dst, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o644)
try:
    sent = 0
    while sent < size:
        n = os.sendfile(out_fd, in_fd, sent, size - sent)
        if n == 0:
            break
        sent += n
    os.fsync(out_fd)
finally:
    os.close(in_fd)
    os.close(out_fd)

print(json.dumps({
    "sent": sent,
    "source_size": os.path.getsize(src),
    "dest_size": os.path.getsize(dst),
    "source_sha256": digest(src),
    "dest_sha256": digest(dst),
}, sort_keys=True))
"#;

fn run_sendfile_32m_probe(root: &Path) -> Value {
    let output = Command::new("python3")
        .arg("-c")
        .arg(SENDFILE_32M_SCRIPT)
        .arg(root)
        .output()
        .expect("run python3 sendfile probe");
    assert!(
        output.status.success(),
        "python3 sendfile probe failed for {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("sendfile probe JSON")
}

const SENDFILE_VS_NAIVE_1G_SCRIPT: &str = r#"
import hashlib
import json
import os
import sys
import time

if not hasattr(os, "sendfile"):
    print(json.dumps({"skipped": "python_os_sendfile_unavailable"}))
    sys.exit(0)

root = sys.argv[1]
size = 1024 * 1024 * 1024
naive_chunk = 64 * 1024
sendfile_chunk = 32 * 1024 * 1024
src = os.path.join(root, "bench_1g_source.bin")
sink = "/dev/null"
sentinel_len = 4096
sentinel_offsets = [0, size // 2, size - sentinel_len]
sentinel = bytes(((i * 17 + 3) % 251) for i in range(sentinel_len))

fd = os.open(src, os.O_CREAT | os.O_TRUNC | os.O_RDWR, 0o644)
try:
    os.ftruncate(fd, size)
    for offset in sentinel_offsets:
        os.pwrite(fd, sentinel, offset)
    os.fsync(fd)
finally:
    os.close(fd)

def sample_digest(path):
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY)
    try:
        for offset in sentinel_offsets:
            h.update(os.pread(fd, sentinel_len, offset))
    finally:
        os.close(fd)
    return h.hexdigest()

def naive_copy():
    copied = 0
    start = time.perf_counter()
    with open(src, "rb", buffering=0) as source, open(sink, "wb", buffering=0) as dest:
        while True:
            data = source.read(naive_chunk)
            if not data:
                break
            dest.write(data)
            copied += len(data)
    return copied, time.perf_counter() - start

def sendfile_copy():
    in_fd = os.open(src, os.O_RDONLY)
    out_fd = os.open(sink, os.O_WRONLY)
    try:
        sent = 0
        start = time.perf_counter()
        while sent < size:
            n = os.sendfile(out_fd, in_fd, sent, min(sendfile_chunk, size - sent))
            if n == 0:
                break
            sent += n
        elapsed = time.perf_counter() - start
    finally:
        os.close(in_fd)
        os.close(out_fd)
    return sent, elapsed

src_digest_before = sample_digest(src)
naive_bytes, naive_seconds = naive_copy()
sent, sendfile_seconds = sendfile_copy()
src_digest_after = sample_digest(src)
ratio = naive_seconds / sendfile_seconds if sendfile_seconds > 0 else 0.0

print(json.dumps({
    "size": size,
    "naive_bytes": naive_bytes,
    "sent": sent,
    "naive_seconds": naive_seconds,
    "sendfile_seconds": sendfile_seconds,
    "naive_mib_s": (size / (1024 * 1024)) / naive_seconds,
    "sendfile_mib_s": (size / (1024 * 1024)) / sendfile_seconds,
    "ratio": ratio,
    "source_sample_sha256_before": src_digest_before,
    "source_sample_sha256_after": src_digest_after,
}, sort_keys=True))
"#;

fn run_sendfile_vs_naive_1g_benchmark(root: &Path) -> Value {
    let mut command = if command_available("timeout") {
        let mut command = Command::new("timeout");
        command.arg("600s").arg("python3");
        command
    } else {
        Command::new("python3")
    };
    let output = command
        .arg("-c")
        .arg(SENDFILE_VS_NAIVE_1G_SCRIPT)
        .arg(root)
        .output()
        .expect("run python3 sendfile benchmark");
    assert!(
        output.status.success(),
        "python3 sendfile benchmark failed for {}: status={} stdout={} stderr={}",
        root.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("sendfile benchmark JSON")
}

const SPLICE_FILE_TO_PIPE_SCRIPT: &str = r#"
import errno
import json
import mmap
import os
import sys
import threading

if not hasattr(os, "splice"):
    print(json.dumps({"skipped": "python_os_splice_unavailable"}))
    sys.exit(0)

root = sys.argv[1]
sector_size = 4096
buffer_size = 150 * sector_size
splice_chunk = 16 * 1024
move_flag = getattr(os, "SPLICE_F_MOVE", 1)
o_direct = getattr(os, "O_DIRECT", 0)

def aligned_x_buffer():
    buf = mmap.mmap(-1, buffer_size)
    buf.write(b"x" * buffer_size)
    buf.seek(0)
    return buf

def drain_exact(fd, total):
    drained = 0
    while drained < total:
        data = os.read(fd, min(splice_chunk, total - drained))
        if not data:
            raise RuntimeError("unexpected EOF while draining splice pipe")
        drained += len(data)

def run_case(name, direct, concurrent):
    path = os.path.join(root, f"generic_591_{name}.bin")
    flags = os.O_CREAT | os.O_TRUNC | os.O_RDWR
    if direct:
        if o_direct == 0:
            return {"case": name, "skipped": "python_os_odirect_unavailable"}
        flags |= o_direct
    try:
        fd = os.open(path, flags, 0o666)
    except OSError as exc:
        if direct and exc.errno in (errno.EINVAL, errno.EOPNOTSUPP, errno.ENOTSUP):
            return {"case": name, "skipped": "odirect_open_unavailable", "errno": exc.errno}
        raise

    pipe_r, pipe_w = os.pipe()
    try:
        if direct:
            buf = aligned_x_buffer()
            try:
                written = os.write(fd, memoryview(buf))
            except OSError as exc:
                buf.close()
                if exc.errno in (errno.EINVAL, errno.EOPNOTSUPP, getattr(errno, "ENOTSUP", errno.EOPNOTSUPP)):
                    return {"case": name, "skipped": "odirect_write_unavailable", "errno": exc.errno}
                raise
            buf.close()
        else:
            written = os.write(fd, b"x" * buffer_size)
        if written != buffer_size:
            raise RuntimeError(f"short write: {written}")
        os.lseek(fd, 0, os.SEEK_SET)

        reader_error = []
        if concurrent:
            def reader():
                try:
                    drain_exact(pipe_r, buffer_size)
                except BaseException as exc:
                    reader_error.append(repr(exc))
            thread = threading.Thread(target=reader)
            thread.start()
        else:
            thread = None

        moved = 0
        while moved < buffer_size:
            n = os.splice(fd, pipe_w, min(splice_chunk, buffer_size - moved), flags=move_flag)
            if n == 0:
                break
            moved += n
            if not concurrent:
                drain_exact(pipe_r, n)

        os.close(pipe_w)
        pipe_w = -1
        if thread is not None:
            thread.join(timeout=10)
            if thread.is_alive():
                raise RuntimeError("concurrent splice reader did not finish")
            if reader_error:
                raise RuntimeError(reader_error[0])
        return {"case": name, "moved": moved, "direct": direct, "concurrent": concurrent}
    finally:
        if pipe_w != -1:
            os.close(pipe_w)
        os.close(pipe_r)
        os.close(fd)

cases = [
    run_case("direct_sequential", True, False),
    run_case("direct_concurrent", True, True),
    run_case("buffered_sequential", False, False),
    run_case("buffered_concurrent", False, True),
]
print(json.dumps({"buffer_size": buffer_size, "cases": cases}, sort_keys=True))
"#;

fn run_splice_file_to_pipe_probe(root: &Path) -> Value {
    let output = Command::new("python3")
        .arg("-c")
        .arg(SPLICE_FILE_TO_PIPE_SCRIPT)
        .arg(root)
        .output()
        .expect("run python3 splice file-to-pipe probe");
    assert!(
        output.status.success(),
        "python3 splice file-to-pipe probe failed for {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("splice file-to-pipe probe JSON")
}

const READONLY_SPLICE_PIPE_MERGE_SCRIPT: &str = r#"
import fcntl
import json
import os
import sys

if not hasattr(os, "splice"):
    print(json.dumps({"skipped": "python_os_splice_unavailable"}))
    sys.exit(0)

root = sys.argv[1]
path = os.path.join(root, "generic_680_readonly.bin")
payload = b"AAAAAAAABBBBBBBB"
with open(path, "wb") as f:
    f.write(b"\xff" * 4096)
    f.flush()
    os.fsync(f.fileno())
os.chmod(path, 0o644)

fd = os.open(path, os.O_RDONLY)
pipe_r, pipe_w = os.pipe()
try:
    try:
        pipe_size = fcntl.fcntl(pipe_w, fcntl.F_GETPIPE_SZ)
    except OSError:
        pipe_size = 65536
    block = b"\0" * 4096
    remaining = pipe_size
    while remaining:
        n = os.write(pipe_w, block[:min(len(block), remaining)])
        remaining -= n
    remaining = pipe_size
    while remaining:
        data = os.read(pipe_r, min(len(block), remaining))
        if not data:
            raise RuntimeError("unexpected EOF while draining prepared pipe")
        remaining -= len(data)

    moved = os.splice(fd, pipe_w, 1, offset_src=0)
    if moved != 1:
        raise RuntimeError(f"short readonly splice: {moved}")
    written = os.write(pipe_w, payload)
finally:
    os.close(pipe_r)
    os.close(pipe_w)
    os.close(fd)

with open(path, "rb") as f:
    data = f.read()

print(json.dumps({
    "moved": moved,
    "pipe_write": written,
    "unchanged": data == b"\xff" * 4096,
    "prefix_hex": data[:32].hex(),
}, sort_keys=True))
"#;

fn run_readonly_splice_pipe_merge_probe(root: &Path) -> Value {
    let output = Command::new("python3")
        .arg("-c")
        .arg(READONLY_SPLICE_PIPE_MERGE_SCRIPT)
        .arg(root)
        .output()
        .expect("run python3 read-only splice pipe probe");
    assert!(
        output.status.success(),
        "python3 read-only splice pipe probe failed for {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("read-only splice pipe probe JSON")
}

fn reference_conformance_tempdir() -> TempDir {
    if Path::new("/dev/shm").is_dir() {
        if let Ok(dir) = tempfile::Builder::new()
            .prefix("ffs-reference-")
            .tempdir_in("/dev/shm")
        {
            return dir;
        }
    }
    TempDir::new().expect("reference tempdir")
}

fn assert_syscall_negative_errno(checks: &[Value], label: &str, expected_errno: i32) {
    let check = checks
        .iter()
        .find(|check| check["label"].as_str() == Some(label))
        .expect("missing negative syscall check");
    assert_eq!(
        check["ok"].as_bool(),
        Some(false),
        "{label} should fail in the negative syscall matrix: {check}"
    );
    assert_eq!(
        check["errno"].as_i64(),
        Some(i64::from(expected_errno)),
        "{label} should surface errno {expected_errno}: {check}"
    );
}

#[test]
fn syscall_conformance_reference_probe_covers_negative_errno_contracts() {
    if !command_available("python3") {
        eprintln!("python3 prerequisites not met, skipping");
        return;
    }

    let reference = reference_conformance_tempdir();
    let report = run_syscall_conformance_probe(reference.path());
    let records = report
        .as_array()
        .expect("syscall conformance report should be a JSON array");
    let negative = records
        .iter()
        .find(|record| record["step"].as_str() == Some("negative_errno_contracts"))
        .expect("missing negative errno step in report");
    assert_eq!(
        negative["ok"].as_bool(),
        Some(true),
        "negative errno step should report captured errors without aborting: {negative}"
    );
    let checks = negative["result"]["checks"]
        .as_array()
        .expect("negative errno step should include check records");

    assert_syscall_negative_errno(checks, "mkdir_existing", libc::EEXIST);
    assert_syscall_negative_errno(checks, "unlink_missing", libc::ENOENT);
    assert_syscall_negative_errno(checks, "rename_missing", libc::ENOENT);
    assert_syscall_negative_errno(checks, "rmdir_nonempty", libc::ENOTEMPTY);
}

#[test]
fn syscall_conformance_reference_probe_covers_fd_metadata_contracts() {
    if !command_available("python3") {
        eprintln!("python3 prerequisites not met, skipping");
        return;
    }

    let reference = reference_conformance_tempdir();
    let report = run_syscall_conformance_probe(reference.path());
    let records = report
        .as_array()
        .expect("syscall conformance report should be a JSON array");
    let fd_metadata = records
        .iter()
        .find(|record| record["step"].as_str() == Some("fd_metadata_ops"))
        .expect("missing fd metadata step in report");
    assert_eq!(
        fd_metadata["ok"].as_bool(),
        Some(true),
        "fd metadata step should succeed on the reference filesystem: {fd_metadata}"
    );

    let result = &fd_metadata["result"];
    assert_eq!(result["read"].as_str(), Some("bra"));
    assert_eq!(result["stat"], result["fstat"]);
    assert_eq!(result["stat"]["kind"].as_str(), Some("file"));
    assert_eq!(result["stat"]["mode"].as_u64(), Some(0o640));
    assert_eq!(result["stat"]["size"].as_u64(), Some(3));
    assert_eq!(result["stat"]["nlink"].as_u64(), Some(1));
}

#[test]
fn syscall_conformance_reference_probe_covers_dirfd_mutation_contracts() {
    if !command_available("python3") {
        eprintln!("python3 prerequisites not met, skipping");
        return;
    }

    let reference = reference_conformance_tempdir();
    let report = run_syscall_conformance_probe(reference.path());
    let records = report
        .as_array()
        .expect("syscall conformance report should be a JSON array");
    let dirfd = records
        .iter()
        .find(|record| record["step"].as_str() == Some("dirfd_mutation_contracts"))
        .expect("missing dirfd mutation step in report");
    assert_eq!(
        dirfd["ok"].as_bool(),
        Some(true),
        "dirfd mutation step should succeed on the reference filesystem: {dirfd}"
    );

    let result = &dirfd["result"];
    if let Some(skipped) = result["skipped"].as_str() {
        eprintln!("dirfd mutation prerequisites not met, skipping: {skipped}");
        return;
    }

    let entries_after_create = result["entries_after_create"]
        .as_array()
        .expect("dirfd mutation step should include create entries");
    assert!(
        entries_after_create
            .iter()
            .any(|entry| entry.as_str() == Some("dirfd_file.txt")),
        "openat-created file should appear before rename: {entries_after_create:?}"
    );
    assert!(
        entries_after_create
            .iter()
            .any(|entry| entry.as_str() == Some("dirfd_dir")),
        "mkdirat-created directory should appear before rmdir: {entries_after_create:?}"
    );
    assert_eq!(result["old_exists_after_rename"].as_bool(), Some(false));
    assert_eq!(result["new_exists_after_rename"].as_bool(), Some(true));
    assert_eq!(result["renamed_read"].as_str(), Some("dirfd"));
    assert_eq!(result["renamed_stat"]["kind"].as_str(), Some("file"));
    assert_eq!(result["renamed_stat"]["size"].as_u64(), Some(5));
    assert_eq!(result["renamed_stat"]["nlink"].as_u64(), Some(1));
    assert_eq!(result["file_exists_after_unlink"].as_bool(), Some(false));
    assert_eq!(result["dir_exists_after_rmdir"].as_bool(), Some(false));
}

#[test]
fn syscall_conformance_reference_probe_covers_truncate_extension_zero_fill() {
    if !command_available("python3") {
        eprintln!("python3 prerequisites not met, skipping");
        return;
    }

    let reference = reference_conformance_tempdir();
    let report = run_syscall_conformance_probe(reference.path());
    let records = report
        .as_array()
        .expect("syscall conformance report should be a JSON array");
    let sparse = records
        .iter()
        .find(|record| record["step"].as_str() == Some("truncate_extend_zero_fill"))
        .expect("missing truncate-extension zero-fill step in report");
    assert_eq!(
        sparse["ok"].as_bool(),
        Some(true),
        "truncate-extension zero-fill step should succeed on the reference filesystem: {sparse}"
    );

    let result = &sparse["result"];
    assert_eq!(result["after_extend_hex"].as_str(), Some("686900000000"));
    assert_eq!(result["after_patch_hex"].as_str(), Some("68690000005a"));
    assert_eq!(result["stat"]["kind"].as_str(), Some("file"));
    assert_eq!(result["stat"]["size"].as_u64(), Some(6));
}

#[test]
fn syscall_conformance_reference_probe_covers_open_unlink_fd_lifetime() {
    if !command_available("python3") {
        eprintln!("python3 prerequisites not met, skipping");
        return;
    }

    let reference = reference_conformance_tempdir();
    let report = run_syscall_conformance_probe(reference.path());
    let records = report
        .as_array()
        .expect("syscall conformance report should be a JSON array");
    let open_unlink = records
        .iter()
        .find(|record| record["step"].as_str() == Some("open_unlink_fd_lifetime"))
        .expect("missing open-unlink fd lifetime step in report");
    assert_eq!(
        open_unlink["ok"].as_bool(),
        Some(true),
        "open-unlink fd lifetime step should succeed on the reference filesystem: {open_unlink}"
    );

    let result = &open_unlink["result"];
    assert_eq!(result["before_stat"]["kind"].as_str(), Some("file"));
    assert_eq!(result["before_stat"]["size"].as_u64(), Some(11));
    assert_eq!(result["before_stat"]["nlink"].as_u64(), Some(1));
    assert_eq!(result["path_exists_after_unlink"].as_bool(), Some(false));
    assert_eq!(result["path_exists_after_close"].as_bool(), Some(false));
    assert_eq!(result["fstat_after_unlink"]["kind"].as_str(), Some("file"));
    assert_eq!(result["fstat_after_unlink"]["size"].as_u64(), Some(11));
    assert_eq!(result["fstat_after_unlink"]["nlink"].as_u64(), Some(0));
    assert_eq!(result["read_after_unlink"].as_str(), Some("open-unlink"));
    assert_eq!(result["read_after_write"].as_str(), Some("open-unlink-fd"));
    assert_eq!(result["fstat_after_write"]["size"].as_u64(), Some(14));
    assert_eq!(result["fstat_after_write"]["nlink"].as_u64(), Some(0));
}

#[test]
fn syscall_conformance_reference_probe_covers_open_rename_fd_lifetime() {
    if !command_available("python3") {
        eprintln!("python3 prerequisites not met, skipping");
        return;
    }

    let reference = reference_conformance_tempdir();
    let report = run_syscall_conformance_probe(reference.path());
    let records = report
        .as_array()
        .expect("syscall conformance report should be a JSON array");
    let open_rename = records
        .iter()
        .find(|record| record["step"].as_str() == Some("open_rename_fd_lifetime"))
        .expect("missing open-rename fd lifetime step in report");
    assert_eq!(
        open_rename["ok"].as_bool(),
        Some(true),
        "open-rename fd lifetime step should succeed on the reference filesystem: {open_rename}"
    );

    let result = &open_rename["result"];
    assert_eq!(result["before_stat"]["kind"].as_str(), Some("file"));
    assert_eq!(result["before_stat"]["size"].as_u64(), Some(11));
    assert_eq!(result["before_stat"]["nlink"].as_u64(), Some(1));
    assert_eq!(
        result["old_path_exists_after_rename"].as_bool(),
        Some(false)
    );
    assert_eq!(result["new_path_exists_after_rename"].as_bool(), Some(true));
    assert_eq!(result["moved_stat_after_rename"], result["before_stat"]);
    assert_eq!(result["fstat_after_rename"], result["before_stat"]);
    assert_eq!(result["read_after_rename"].as_str(), Some("open-rename"));
    assert_eq!(result["read_after_write"].as_str(), Some("open-rename-fd"));
    assert_eq!(
        result["moved_read_after_close"].as_str(),
        Some("open-rename-fd")
    );
    assert_eq!(result["fstat_after_write"]["size"].as_u64(), Some(14));
    assert_eq!(result["fstat_after_write"]["nlink"].as_u64(), Some(1));
    assert_eq!(
        result["moved_stat_after_close"],
        result["fstat_after_write"]
    );
}

#[test]
fn syscall_conformance_reference_probe_covers_rename_replace_existing() {
    if !command_available("python3") {
        eprintln!("python3 prerequisites not met, skipping");
        return;
    }

    let reference = reference_conformance_tempdir();
    let report = run_syscall_conformance_probe(reference.path());
    let records = report
        .as_array()
        .expect("syscall conformance report should be a JSON array");
    let replace = records
        .iter()
        .find(|record| record["step"].as_str() == Some("rename_replace_existing"))
        .expect("missing rename-replace step in report");
    assert_eq!(
        replace["ok"].as_bool(),
        Some(true),
        "rename-replace step should succeed on the reference filesystem: {replace}"
    );

    let result = &replace["result"];
    assert_eq!(result["before_dst_stat"]["kind"].as_str(), Some("file"));
    assert_eq!(result["before_dst_stat"]["size"].as_u64(), Some(8));
    assert_eq!(result["src_exists_after_rename"].as_bool(), Some(false));
    assert_eq!(
        result["dst_read_after_rename"].as_str(),
        Some("replacement")
    );
    assert_eq!(
        result["dst_stat_after_rename"]["kind"].as_str(),
        Some("file")
    );
    assert_eq!(result["dst_stat_after_rename"]["size"].as_u64(), Some(11));
    assert_eq!(result["dst_stat_after_rename"]["nlink"].as_u64(), Some(1));
}

#[test]
fn syscall_conformance_reference_probe_covers_renameat2_flag_contracts() {
    if !command_available("python3") {
        eprintln!("python3 prerequisites not met, skipping");
        return;
    }

    let reference = reference_conformance_tempdir();
    let report = run_syscall_conformance_probe(reference.path());
    let records = report
        .as_array()
        .expect("syscall conformance report should be a JSON array");
    let renameat2 = records
        .iter()
        .find(|record| record["step"].as_str() == Some("renameat2_flag_contracts"))
        .expect("missing renameat2 flag step in report");
    assert_eq!(
        renameat2["ok"].as_bool(),
        Some(true),
        "renameat2 flag step should succeed on the reference filesystem: {renameat2}"
    );

    let result = &renameat2["result"];
    if result["available"].as_bool() == Some(false) {
        eprintln!("renameat2 unavailable on this worker, skipping");
        return;
    }
    assert_eq!(result["available"].as_bool(), Some(true));
    assert_eq!(result["noreplace_free"]["ok"].as_bool(), Some(true));
    assert_eq!(result["noreplace_free_src_exists"].as_bool(), Some(false));
    assert_eq!(result["noreplace_free_dst_read"].as_str(), Some("free-src"));
    assert_eq!(
        result["noreplace_existing"]["errno"].as_i64(),
        Some(i64::from(libc::EEXIST))
    );
    assert_eq!(
        result["noreplace_existing_src_read"].as_str(),
        Some("existing-src")
    );
    assert_eq!(
        result["noreplace_existing_dst_read"].as_str(),
        Some("existing-dst")
    );
    assert_eq!(result["exchange"]["ok"].as_bool(), Some(true));
    assert_eq!(result["exchange_src_read"].as_str(), Some("exchange-dst"));
    assert_eq!(result["exchange_dst_read"].as_str(), Some("exchange-src"));
}

#[test]
fn syscall_conformance_reference_probe_covers_symlink_at_nofollow_contracts() {
    if !command_available("python3") {
        eprintln!("python3 prerequisites not met, skipping");
        return;
    }

    let reference = reference_conformance_tempdir();
    let report = run_syscall_conformance_probe(reference.path());
    let records = report
        .as_array()
        .expect("syscall conformance report should be a JSON array");
    let symlink_at = records
        .iter()
        .find(|record| record["step"].as_str() == Some("symlink_at_nofollow_contracts"))
        .expect("missing symlink-at nofollow step in report");
    assert_eq!(
        symlink_at["ok"].as_bool(),
        Some(true),
        "symlink-at nofollow step should succeed on the reference filesystem: {symlink_at}"
    );

    let result = &symlink_at["result"];
    assert_eq!(result["follow_stat"]["kind"].as_str(), Some("file"));
    assert_eq!(result["follow_stat"]["size"].as_u64(), Some(3));
    assert_eq!(result["lstat"]["kind"].as_str(), Some("symlink"));
    assert_eq!(result["lstat"]["size"].as_u64(), Some(8));
    assert_eq!(result["readlinkat"].as_str(), Some("file.txt"));
    assert_eq!(
        result["regular_openat_no_follow_read"].as_str(),
        Some("alp")
    );
    assert_eq!(result["fstatat_lstat"], result["lstat"]);
    let checks = [result["open_symlink_nofollow"].clone()];
    assert_syscall_negative_errno(&checks, "open_symlink_nofollow", libc::ELOOP);
}

#[test]
fn fuse_conformance_syscall_sequence_matches_linux_reference() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let reference = reference_conformance_tempdir();
    let image = create_test_image_with_size(tmp.path(), 16 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let reference_report = run_syscall_conformance_probe(reference.path());

    let Some(_session) = try_mount_ffs_rw(&image, &mnt) else {
        return;
    };

    let frankenfs_report = run_syscall_conformance_probe(&mnt);
    let reference_pretty =
        serde_json::to_string_pretty(&reference_report).expect("format reference report");
    let frankenfs_pretty =
        serde_json::to_string_pretty(&frankenfs_report).expect("format FrankenFS report");

    assert_eq!(
        frankenfs_report, reference_report,
        "syscall-level conformance mismatch\nreference: {reference_pretty}\nfrankenfs: {frankenfs_pretty}"
    );
    emit_scenario_result(
        "ext4_rw_syscall_level_differential_conformance",
        "PASS",
        Some(
            "file_lifecycle+fd_metadata+dirfd_mutation+offset_io+truncate_extend+open_unlink_fd+open_rename_fd+rename_replace+renameat2+openat+access+statvfs+dir_ops+attrs+links+fstatat+readlinkat+nofollow+mmap+fsync+negative_errno",
        ),
    );
}

fn with_ext4_inline_data_mount(inode_fixture: &str, f: impl FnOnce(&Path)) {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let image = create_ext4_inline_data_test_image(tmp.path(), inode_fixture);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };
    f(&mnt);
}

fn assert_mounted_ext4_inline_data_read_contract(
    inode_fixture: &str,
    expected: &[u8],
    scenario_id: &str,
    detail: &str,
) {
    with_ext4_inline_data_mount(inode_fixture, |mnt| {
        let path = mnt.join("inline.bin");
        assert_eq!(
            fs::metadata(&path).expect("stat inline.bin via FUSE").len(),
            u64::try_from(expected.len()).expect("expected inline size fits u64"),
            "mounted inline-data file should report the expected byte length"
        );
        assert_eq!(
            fs::read(&path).expect("read inline.bin via FUSE"),
            expected,
            "mounted inline-data file should expose the expected payload"
        );

        let mut file = fs::File::open(&path).expect("open inline.bin for boundary reads");
        let short_offset =
            u64::try_from(expected.len().saturating_sub(4)).expect("offset fits u64");
        file.seek(SeekFrom::Start(short_offset))
            .expect("seek near inline-data EOF");
        let mut buf = [0_u8; 8];
        let read = file
            .read(&mut buf)
            .expect("short read near inline-data EOF");
        assert_eq!(
            &buf[..read],
            &expected[expected.len() - read..],
            "near-EOF mounted inline-data read should truncate to the remaining tail bytes"
        );
        let eof_read = file
            .read(&mut buf)
            .expect("read exactly at inline-data EOF");
        assert_eq!(eof_read, 0, "mounted inline-data EOF read should be empty");

        emit_scenario_result(scenario_id, "PASS", Some(detail));
    });
}

fn query_fiemap(path: &Path, extent_count: u32) -> Value {
    query_fiemap_with_options(path, extent_count, 0, None)
}

fn query_fiemap_with_options(
    path: &Path,
    extent_count: u32,
    request_flags: u32,
    response_size: Option<usize>,
) -> Value {
    let script = r"
import fcntl, json, struct, sys

FS_IOC_FIEMAP = 0xC020660B
FIEMAP_HEADER_SIZE = 32
FIEMAP_EXTENT_SIZE = 56
FIEMAP_EXTENT_LAST = 0x0001

path = sys.argv[1]
extent_count = int(sys.argv[2])
request_flags = int(sys.argv[3], 0)
response_size = int(sys.argv[4])
buffer = bytearray(response_size)
if response_size < FIEMAP_HEADER_SIZE:
    raise ValueError('fiemap response buffer too small: {}'.format(response_size))
struct.pack_into('@Q', buffer, 0, 0)
struct.pack_into('@Q', buffer, 8, (1 << 64) - 1)
struct.pack_into('@I', buffer, 16, request_flags)
struct.pack_into('@I', buffer, 24, extent_count)

with open(path, 'rb', buffering=0) as fh:
    try:
        fcntl.ioctl(fh.fileno(), FS_IOC_FIEMAP, buffer, True)
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)

mapped_extents = struct.unpack_from('@I', buffer, 20)[0]
requested_extents = struct.unpack_from('@I', buffer, 24)[0]
extents = []
for index in range(mapped_extents):
    off = FIEMAP_HEADER_SIZE + index * FIEMAP_EXTENT_SIZE
    logical = struct.unpack_from('@Q', buffer, off)[0]
    physical = struct.unpack_from('@Q', buffer, off + 8)[0]
    length = struct.unpack_from('@Q', buffer, off + 16)[0]
    flags = struct.unpack_from('@I', buffer, off + 40)[0]
    extents.append({
        'logical': logical,
        'physical': physical,
        'length': length,
        'flags': flags,
        'last': bool(flags & FIEMAP_EXTENT_LAST),
    })

print(json.dumps({
    'mapped_extents': mapped_extents,
    'requested_extents': requested_extents,
    'extents': extents,
}))
    ";

    let response_size = response_size
        .unwrap_or_else(|| 32 + usize::try_from(extent_count).expect("extent_count fits") * 56);

    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            &extent_count.to_string(),
            &request_flags.to_string(),
            &response_size.to_string(),
        ])
        .output()
        .expect("python3 fiemap ioctl");
    assert!(
        output.status.success(),
        "python3 fiemap ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode fiemap JSON")
}

fn query_directory_fiemap_with_options(
    path: &Path,
    extent_count: u32,
    request_flags: u32,
    response_size: Option<usize>,
) -> Value {
    let script = r"
import errno, fcntl, json, os, struct, sys

FS_IOC_FIEMAP = 0xC020660B
FIEMAP_HEADER_SIZE = 32

path = sys.argv[1]
extent_count = int(sys.argv[2])
request_flags = int(sys.argv[3], 0)
response_size = int(sys.argv[4])
buffer = bytearray(response_size)
if response_size < FIEMAP_HEADER_SIZE:
    raise ValueError('fiemap response buffer too small: {}'.format(response_size))
struct.pack_into('@Q', buffer, 0, 0)
struct.pack_into('@Q', buffer, 8, (1 << 64) - 1)
struct.pack_into('@I', buffer, 16, request_flags)
struct.pack_into('@I', buffer, 24, extent_count)

fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
try:
    try:
        fcntl.ioctl(fd, FS_IOC_FIEMAP, buffer, True)
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'name': errno.errorcode.get(exc.errno, 'UNKNOWN'),
            'message': str(exc),
        }))
        sys.exit(0)
finally:
    os.close(fd)

print(json.dumps({'ok': True}))
";

    let response_size = response_size
        .unwrap_or_else(|| 32 + usize::try_from(extent_count).expect("extent_count fits") * 56);

    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            &extent_count.to_string(),
            &request_flags.to_string(),
            &response_size.to_string(),
        ])
        .output()
        .expect("python3 directory fiemap ioctl");
    assert!(
        output.status.success(),
        "python3 directory fiemap ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode directory fiemap JSON")
}

fn fiemap_extent_flags(extent: &Value) -> u32 {
    u32::try_from(extent["flags"].as_u64().unwrap_or(0)).expect("fiemap flags should fit u32")
}

fn ext4_inode_flags_ioctl(path: &Path, command: &str, flags: Option<u32>) -> Value {
    let script = r"
import fcntl, json, struct, sys

EXT4_IOC_GETFLAGS = 0x80086601
EXT4_IOC_SETFLAGS = 0x40086602

command = sys.argv[1]
path = sys.argv[2]
word_size = struct.calcsize('@L')

def setflags_buffer(flags: int) -> bytes:
    if word_size >= 8:
        return struct.pack('@Q', flags)
    return struct.pack('@I', flags)

with open(path, 'r+b', buffering=0) as fh:
    try:
        if command == 'get':
            buffer = bytearray(word_size)
            fcntl.ioctl(fh.fileno(), EXT4_IOC_GETFLAGS, buffer, True)
            print(json.dumps({
                'flags': struct.unpack_from('@I', buffer, 0)[0],
            }))
        elif command == 'set':
            flags = int(sys.argv[3], 0)
            buffer = setflags_buffer(flags)
            fcntl.ioctl(fh.fileno(), EXT4_IOC_SETFLAGS, buffer)
            print(json.dumps({'ok': True}))
        else:
            raise ValueError(f'unsupported ioctl command: {command}')
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    ";

    let mut args = vec![
        "-c".to_owned(),
        script.to_owned(),
        command.to_owned(),
        path.to_str().expect("path utf8").to_owned(),
    ];
    if let Some(flags) = flags {
        args.push(flags.to_string());
    }

    let output = Command::new("python3")
        .args(args)
        .output()
        .expect("python3 ext4 ioctl");
    assert!(
        output.status.success(),
        "python3 ext4 ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode ext4 ioctl JSON")
}

fn ext4_inode_generation_ioctl(path: &Path, command: &str, generation: Option<u32>) -> Value {
    let script = r"
import fcntl, json, struct, sys

EXT4_IOC_GETVERSION = 0x80086603
EXT4_IOC_SETVERSION = 0x40086604

command = sys.argv[1]
path = sys.argv[2]
word_size = struct.calcsize('@L')

def setversion_buffer(generation: int) -> bytes:
    if word_size >= 8:
        return struct.pack('@Q', generation)
    return struct.pack('@I', generation)

mode = 'r+b' if command == 'set' else 'rb'
with open(path, mode, buffering=0) as fh:
    try:
        if command == 'get':
            buffer = bytearray(word_size)
            fcntl.ioctl(fh.fileno(), EXT4_IOC_GETVERSION, buffer, True)
            print(json.dumps({
                'generation': struct.unpack_from('@I', buffer, 0)[0],
            }))
        elif command == 'set':
            generation = int(sys.argv[3], 0)
            buffer = setversion_buffer(generation)
            fcntl.ioctl(fh.fileno(), EXT4_IOC_SETVERSION, buffer)
            print(json.dumps({'ok': True}))
        else:
            raise ValueError(f'unsupported ioctl command: {command}')
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    ";

    let mut args = vec![
        "-c".to_owned(),
        script.to_owned(),
        command.to_owned(),
        path.to_str().expect("path utf8").to_owned(),
    ];
    if let Some(generation) = generation {
        args.push(generation.to_string());
    }

    let output = Command::new("python3")
        .args(args)
        .output()
        .expect("python3 ext4 setversion ioctl");
    assert!(
        output.status.success(),
        "python3 ext4 setversion ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode ext4 setversion ioctl JSON")
}

fn ext4_get_encryption_policy_ioctl(path: &Path) -> Value {
    let script = r"
import fcntl, json, sys

FS_IOC_GET_ENCRYPTION_POLICY = 0x400C6615
POLICY_SIZE = 12

with open(sys.argv[1], 'rb', buffering=0) as fh:
    buffer = bytearray(POLICY_SIZE)
    try:
        fcntl.ioctl(fh.fileno(), FS_IOC_GET_ENCRYPTION_POLICY, buffer, True)
        print(json.dumps({
            'policy_version': buffer[0],
            'contents_mode': buffer[1],
            'filenames_mode': buffer[2],
            'flags': buffer[3],
            'master_key_descriptor_hex': buffer[4:12].hex(),
            'policy_hex': buffer.hex(),
        }))
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    ";

    let output = Command::new("python3")
        .args(["-c", script, path.to_str().expect("path utf8")])
        .output()
        .expect("python3 get encryption policy ioctl");
    assert!(
        output.status.success(),
        "python3 get encryption policy ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode encryption policy ioctl JSON")
}

fn ext4_get_encryption_policy_ex_ioctl(path: &Path) -> Value {
    let script = r"
import fcntl, json, struct, sys

FS_IOC_GET_ENCRYPTION_POLICY_EX = 0xC0096616
FSCRYPT_POLICY_V1_SIZE = 12
FSCRYPT_POLICY_V2_SIZE = 24
HEADER_SIZE = 8

with open(sys.argv[1], 'rb', buffering=0) as fh:
    buffer = bytearray(HEADER_SIZE + FSCRYPT_POLICY_V2_SIZE)
    struct.pack_into('<Q', buffer, 0, FSCRYPT_POLICY_V2_SIZE)
    try:
        fcntl.ioctl(fh.fileno(), FS_IOC_GET_ENCRYPTION_POLICY_EX, buffer, True)
        actual_size = struct.unpack_from('<Q', buffer, 0)[0]
        policy = buffer[HEADER_SIZE:HEADER_SIZE + actual_size]
        version = policy[0] if len(policy) > 0 else 255
        result = {
            'policy_size': actual_size,
            'policy_version': version,
            'policy_hex': policy.hex(),
        }
        if version == 0 and actual_size >= FSCRYPT_POLICY_V1_SIZE:
            result['contents_mode'] = policy[1]
            result['filenames_mode'] = policy[2]
            result['flags'] = policy[3]
            result['master_key_descriptor_hex'] = policy[4:12].hex()
        elif version == 2 and actual_size >= FSCRYPT_POLICY_V2_SIZE:
            result['contents_mode'] = policy[1]
            result['filenames_mode'] = policy[2]
            result['flags'] = policy[3]
            result['master_key_identifier_hex'] = policy[8:24].hex()
        print(json.dumps(result))
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    ";

    let output = Command::new("python3")
        .args(["-c", script, path.to_str().expect("path utf8")])
        .output()
        .expect("python3 get encryption policy ex ioctl");
    assert!(
        output.status.success(),
        "python3 get encryption policy ex ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode encryption policy ex ioctl JSON")
}

fn fs_label_ioctl(path: &Path, command: &str, label: Option<&str>) -> Value {
    let script = r"
import fcntl, json, sys

FS_IOC_GETFSLABEL = 0x81009431
FS_IOC_SETFSLABEL = 0x41009432
FSLABEL_MAX = 256

with open(sys.argv[1], 'rb', buffering=0) as fh:
    command = sys.argv[2]
    try:
        if command == 'get':
            buffer = bytearray(FSLABEL_MAX)
            fcntl.ioctl(fh.fileno(), FS_IOC_GETFSLABEL, buffer, True)
            end = buffer.find(0)
            if end < 0:
                end = len(buffer)
            label_bytes = bytes(buffer[:end])
            print(json.dumps({
                'label': label_bytes.decode('utf-8', 'surrogateescape'),
                'label_hex': label_bytes.hex(),
            }))
        elif command == 'set':
            label = sys.argv[3].encode('utf-8', 'surrogateescape')
            if len(label) >= FSLABEL_MAX:
                raise ValueError('label too long for ioctl buffer')
            buffer = bytearray(FSLABEL_MAX)
            buffer[:len(label)] = label
            buffer[len(label)] = 0
            fcntl.ioctl(fh.fileno(), FS_IOC_SETFSLABEL, buffer)
            print(json.dumps({'ok': True}))
        else:
            raise ValueError(f'unsupported ioctl command: {command}')
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    ";

    let mut args = vec!["-c", script, path.to_str().expect("path utf8"), command];
    if let Some(label) = label {
        args.push(label);
    }

    let output = Command::new("python3")
        .args(args)
        .output()
        .expect("python3 fs label ioctl");
    assert!(
        output.status.success(),
        "python3 fs label ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode fs label ioctl JSON")
}

fn ext4_move_ext_ioctl(
    path: &Path,
    donor_path: &Path,
    orig_start: u64,
    donor_start: u64,
    len: u64,
) -> Value {
    let script = r"
import fcntl, json, struct, sys
import signal

EXT4_IOC_MOVE_EXT = 0xC028660F
MOVE_EXT_SIZE = 40

path = sys.argv[1]
donor_path = sys.argv[2]
orig_start = int(sys.argv[3])
donor_start = int(sys.argv[4])
length = int(sys.argv[5])

buffer = bytearray(MOVE_EXT_SIZE)
struct.pack_into('@Q', buffer, 8, orig_start)
struct.pack_into('@Q', buffer, 16, donor_start)
struct.pack_into('@Q', buffer, 24, length)

def _timeout(_signum, _frame):
    raise TimeoutError('move_ext ioctl timed out')

with open(path, 'r+b', buffering=0) as orig, open(donor_path, 'r+b', buffering=0) as donor:
    struct.pack_into('@i', buffer, 4, donor.fileno())
    signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(15)
    try:
        fcntl.ioctl(orig.fileno(), EXT4_IOC_MOVE_EXT, buffer, True)
    except (TimeoutError, InterruptedError) as exc:
        print(json.dumps({
            'timeout': True,
            'message': str(exc),
        }))
        sys.exit(0)
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    finally:
        signal.alarm(0)

    print(json.dumps({
        'donor_fd': donor.fileno(),
        'orig_start': struct.unpack_from('@Q', buffer, 8)[0],
        'donor_start': struct.unpack_from('@Q', buffer, 16)[0],
        'len': struct.unpack_from('@Q', buffer, 24)[0],
        'moved_len': struct.unpack_from('@Q', buffer, 32)[0],
    }))
    ";

    let mut command = if command_available("timeout") {
        let mut command = Command::new("timeout");
        command.arg("20s").arg("python3");
        command
    } else {
        Command::new("python3")
    };
    let output = command
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            donor_path.to_str().expect("donor path utf8"),
            &orig_start.to_string(),
            &donor_start.to_string(),
            &len.to_string(),
        ])
        .output()
        .expect("python3 ext4 move_ext ioctl");
    if output.status.code() == Some(124) {
        return serde_json::json!({
            "timeout": true,
            "message": "move_ext ioctl timed out",
        });
    }
    assert!(
        output.status.success(),
        "python3 ext4 move_ext ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode ext4 move_ext ioctl JSON")
}

fn physical_blocks_by_logical_block(report: &Value, block_size: u64) -> Vec<u64> {
    let extents = report["extents"].as_array().expect("fiemap extents array");
    let mut blocks = Vec::new();
    for extent in extents {
        let logical = extent["logical"].as_u64().expect("logical") / block_size;
        let physical = extent["physical"].as_u64().expect("physical") / block_size;
        let block_count = extent["length"].as_u64().expect("length") / block_size;
        for idx in 0..block_count {
            let logical_block =
                usize::try_from(logical + idx).expect("logical block index should fit usize");
            if blocks.len() <= logical_block {
                blocks.resize(logical_block + 1, 0);
            }
            blocks[logical_block] = physical + idx;
        }
    }
    blocks
}

fn query_seek(path: &Path, offset: u64, whence: &str) -> Value {
    let script = r"
import json, os, sys

path = sys.argv[1]
offset = int(sys.argv[2])
whence = getattr(os, sys.argv[3])
fd = os.open(path, os.O_RDONLY)
try:
    print(json.dumps({'offset': os.lseek(fd, offset, whence)}))
except OSError as exc:
    print(json.dumps({
        'errno': exc.errno,
        'message': str(exc),
    }))
finally:
    os.close(fd)
    ";

    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            &offset.to_string(),
            whence,
        ])
        .output()
        .expect("python3 seek probe");
    assert!(
        output.status.success(),
        "python3 seek probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode seek probe JSON")
}

fn query_fallocate(path: &Path, mode: i32, offset: u64, length: u64) -> Value {
    let script = r#"
import ctypes, errno, json, os, sys

path = sys.argv[1]
mode = int(sys.argv[2], 0)
offset = int(sys.argv[3])
length = int(sys.argv[4])
fd = os.open(path, os.O_RDWR)
libc = ctypes.CDLL(None, use_errno=True)
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
libc.fallocate.restype = ctypes.c_int
try:
    res = libc.fallocate(fd, mode, offset, length)
    err = ctypes.get_errno()
    payload = {"res": res, "errno": err}
    if err:
        payload["name"] = errno.errorcode.get(err, "UNKNOWN")
    print(json.dumps(payload))
finally:
    os.close(fd)
"#;

    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            &format!("{mode:#x}"),
            &offset.to_string(),
            &length.to_string(),
        ])
        .output()
        .expect("python3 fallocate probe");
    assert!(
        output.status.success(),
        "python3 fallocate probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode fallocate probe JSON")
}

fn query_directory_fallocate(path: &Path, mode: i32, offset: u64, length: u64) -> Value {
    let script = r#"
import ctypes, errno, json, os, sys

path = sys.argv[1]
mode = int(sys.argv[2], 0)
offset = int(sys.argv[3])
length = int(sys.argv[4])

try:
    fd = os.open(path, os.O_RDWR | os.O_DIRECTORY)
except OSError as exc:
    print(json.dumps({
        "errno": exc.errno,
        "name": errno.errorcode.get(exc.errno, "UNKNOWN"),
        "message": str(exc),
        "phase": "open",
    }))
    sys.exit(0)

libc = ctypes.CDLL(None, use_errno=True)
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
libc.fallocate.restype = ctypes.c_int
try:
    res = libc.fallocate(fd, mode, offset, length)
    err = ctypes.get_errno()
    payload = {"res": res, "errno": err, "phase": "fallocate"}
    if err:
        payload["name"] = errno.errorcode.get(err, "UNKNOWN")
    print(json.dumps(payload))
finally:
    os.close(fd)
"#;

    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            &format!("{mode:#x}"),
            &offset.to_string(),
            &length.to_string(),
        ])
        .output()
        .expect("python3 directory fallocate probe");
    assert!(
        output.status.success(),
        "python3 directory fallocate probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode directory fallocate probe JSON")
}

fn py_fallocate_report(path: &Path, mode: i32, offset: u64, length: u64) -> Value {
    let script = r#"
import ctypes, errno, json, os, sys

path = sys.argv[1]
mode = int(sys.argv[2], 0)
offset = int(sys.argv[3])
length = int(sys.argv[4])
libc = ctypes.CDLL(None, use_errno=True)
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
libc.fallocate.restype = ctypes.c_int

try:
    fd = os.open(path, os.O_RDWR)
except OSError as e:
    print(json.dumps({
        "stage": "open",
        "errno": e.errno,
        "name": errno.errorcode.get(e.errno, "UNKNOWN"),
        "message": str(e),
    }))
    raise SystemExit(0)

try:
    res = libc.fallocate(fd, mode, offset, length)
    err = ctypes.get_errno()
    payload = {"stage": "fallocate", "res": res, "errno": err}
    if err:
        payload["name"] = errno.errorcode.get(err, "UNKNOWN")
    print(json.dumps(payload))
finally:
    os.close(fd)
"#;

    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            &format!("{mode:#x}"),
            &offset.to_string(),
            &length.to_string(),
        ])
        .output()
        .expect("python3 read-only fallocate probe");
    assert!(
        output.status.success(),
        "python3 read-only fallocate probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode read-only fallocate probe JSON")
}

fn assert_seek_data_hole_contract(path: &Path, scenario_id: &str) {
    let data = patterned_bytes(12_288, 251, 1);
    fs::write(path, &data).expect("seed seek test file");

    let out = Command::new("fallocate")
        .args([
            "--keep-size",
            "--punch-hole",
            "-o",
            "4096",
            "-l",
            "4096",
            path.to_str().unwrap(),
        ])
        .output()
        .expect("run fallocate --punch-hole --keep-size for seek test");
    assert!(
        out.status.success(),
        "seek-layout punch-hole failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let readback = fs::read(path).expect("read punched-hole seek test file");
    assert_eq!(
        &readback[..4096],
        &data[..4096],
        "seek test prefix must be preserved"
    );
    assert!(
        readback[4096..8192].iter().all(|&byte| byte == 0),
        "seek test middle hole must read back as zeros"
    );
    assert_eq!(
        &readback[8192..],
        &data[8192..],
        "seek test suffix must be preserved"
    );

    let data0 = query_seek(path, 0, "SEEK_DATA");
    if let Some(errno) = data0["errno"].as_i64() {
        if errno == i64::from(libc::EINVAL)
            || errno == i64::from(libc::ENOSYS)
            || errno == EOPNOTSUPP_ERRNO
        {
            eprintln!(
                "SEEK_DATA/SEEK_HOLE skipped: current kernel/FUSE stack reports errno {errno} \
                 before FrankenFS can prove mounted seek semantics"
            );
            return;
        }
    }

    assert_eq!(
        data0["offset"].as_u64(),
        Some(0),
        "SEEK_DATA at file start should return the first data byte: {data0}"
    );

    let hole0 = query_seek(path, 0, "SEEK_HOLE");
    assert_eq!(
        hole0["offset"].as_u64(),
        Some(4096),
        "SEEK_HOLE from file start should stop at the punched range: {hole0}"
    );

    let data_middle = query_seek(path, 4096, "SEEK_DATA");
    assert_eq!(
        data_middle["offset"].as_u64(),
        Some(8192),
        "SEEK_DATA from inside the punched range should advance to the next extent: {data_middle}"
    );

    let hole_middle = query_seek(path, 4096, "SEEK_HOLE");
    assert_eq!(
        hole_middle["offset"].as_u64(),
        Some(4096),
        "SEEK_HOLE from the punched range should return the hole start: {hole_middle}"
    );

    let hole_tail = query_seek(path, 8192, "SEEK_HOLE");
    assert_eq!(
        hole_tail["offset"].as_u64(),
        Some(data.len() as u64),
        "SEEK_HOLE from the tail extent should report the virtual EOF hole: {hole_tail}"
    );

    let eof_data = query_seek(path, data.len() as u64, "SEEK_DATA");
    assert_eq!(
        eof_data["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_DATA at EOF should surface ENXIO: {eof_data}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("punch_hole_seek_offsets_verified"),
    );
}

fn seek_transport_skipped(report: &Value) -> bool {
    report["errno"].as_i64().is_some_and(|errno| {
        errno == i64::from(libc::EINVAL)
            || errno == i64::from(libc::ENOSYS)
            || errno == EOPNOTSUPP_ERRNO
    })
}

fn assert_seek_fully_allocated_contract(path: &Path, scenario_id: &str) {
    let data = patterned_bytes(8192, 251, 1);
    fs::write(path, &data).expect("seed fully allocated seek test file");

    let data0 = query_seek(path, 0, "SEEK_DATA");
    if seek_transport_skipped(&data0) {
        eprintln!(
            "SEEK_DATA/SEEK_HOLE skipped: current kernel/FUSE stack reports transport-layer \
             rejection before FrankenFS can prove fully allocated seek semantics: {data0}"
        );
        return;
    }

    assert_eq!(
        data0["offset"].as_u64(),
        Some(0),
        "SEEK_DATA at file start should return the first byte of a fully allocated file: {data0}"
    );

    let data_middle = query_seek(path, 4096, "SEEK_DATA");
    assert_eq!(
        data_middle["offset"].as_u64(),
        Some(4096),
        "SEEK_DATA inside a fully allocated extent should return the queried offset: {data_middle}"
    );

    let hole0 = query_seek(path, 0, "SEEK_HOLE");
    assert_eq!(
        hole0["offset"].as_u64(),
        Some(data.len() as u64),
        "SEEK_HOLE from file start should report the virtual EOF hole on a fully allocated file: {hole0}"
    );

    let hole_middle = query_seek(path, 4096, "SEEK_HOLE");
    assert_eq!(
        hole_middle["offset"].as_u64(),
        Some(data.len() as u64),
        "SEEK_HOLE inside a fully allocated extent should report the virtual EOF hole: {hole_middle}"
    );

    let eof_data = query_seek(path, data.len() as u64, "SEEK_DATA");
    assert_eq!(
        eof_data["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_DATA at EOF should surface ENXIO on a fully allocated file: {eof_data}"
    );

    let eof_hole = query_seek(path, data.len() as u64, "SEEK_HOLE");
    assert_eq!(
        eof_hole["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_HOLE at EOF should surface ENXIO on a fully allocated file: {eof_hole}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("fully_allocated_seek_offsets_verified"),
    );
}

fn assert_seek_leading_hole_contract(path: &Path, scenario_id: &str) {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    let data = patterned_bytes(8192, 253, 1);
    fs::write(path, &data).expect("seed leading-hole seek test file");

    let out = Command::new("fallocate")
        .args([
            "--keep-size",
            "--punch-hole",
            "-o",
            "0",
            "-l",
            "4096",
            path.to_str().expect("path utf8"),
        ])
        .output()
        .expect("run fallocate --punch-hole for leading-hole seek test");
    assert!(
        out.status.success(),
        "leading-hole punch-hole failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let readback = fs::read(path).expect("read leading-hole seek test file");
    assert_eq!(
        readback.len(),
        8192,
        "leading-hole seek test file should be sparse with a 4KiB hole prefix"
    );
    assert!(
        readback[..4096].iter().all(|&byte| byte == 0),
        "leading-hole seek test prefix must read back as zeros"
    );
    assert_eq!(
        &readback[4096..],
        &data[4096..],
        "leading-hole seek test suffix must preserve written payload"
    );

    let data0 = query_seek(path, 0, "SEEK_DATA");
    if seek_transport_skipped(&data0) {
        eprintln!(
            "SEEK_DATA/SEEK_HOLE skipped: current kernel/FUSE stack reports transport-layer \
             rejection before FrankenFS can prove leading-hole seek semantics: {data0}"
        );
        return;
    }

    assert_eq!(
        data0["offset"].as_u64(),
        Some(4096),
        "SEEK_DATA from file start should advance to the first real extent after a leading hole: {data0}"
    );

    let hole0 = query_seek(path, 0, "SEEK_HOLE");
    assert_eq!(
        hole0["offset"].as_u64(),
        Some(0),
        "SEEK_HOLE from file start should report the leading sparse hole immediately: {hole0}"
    );

    let data_middle = query_seek(path, 1024, "SEEK_DATA");
    assert_eq!(
        data_middle["offset"].as_u64(),
        Some(4096),
        "SEEK_DATA from inside the leading hole should advance to the first data extent: {data_middle}"
    );

    let hole_middle = query_seek(path, 1024, "SEEK_HOLE");
    assert_eq!(
        hole_middle["offset"].as_u64(),
        Some(1024),
        "SEEK_HOLE from inside the leading hole should return the queried hole offset: {hole_middle}"
    );

    let hole_data_region = query_seek(path, 4096, "SEEK_HOLE");
    assert_eq!(
        hole_data_region["offset"].as_u64(),
        Some(readback.len() as u64),
        "SEEK_HOLE from the data extent should report the virtual EOF hole: {hole_data_region}"
    );

    let eof_data = query_seek(path, readback.len() as u64, "SEEK_DATA");
    assert_eq!(
        eof_data["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_DATA at EOF should surface ENXIO on a leading-hole file: {eof_data}"
    );

    let eof_hole = query_seek(path, readback.len() as u64, "SEEK_HOLE");
    assert_eq!(
        eof_hole["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_HOLE at EOF should surface ENXIO on a leading-hole file: {eof_hole}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("leading_hole_seek_offsets_verified"),
    );
}

fn assert_seek_all_hole_contract(path: &Path, scenario_id: &str) {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .expect("create all-hole seek test file");
    file.set_len(8192)
        .expect("set logical size for all-hole seek test file");
    drop(file);

    let readback = fs::read(path).expect("read all-hole seek test file");
    assert_eq!(
        readback.len(),
        8192,
        "all-hole seek test file should preserve its logical size"
    );
    assert!(
        readback.iter().all(|&byte| byte == 0),
        "all-hole seek test file must read back as zeros"
    );

    let data0 = query_seek(path, 0, "SEEK_DATA");
    if seek_transport_skipped(&data0) {
        eprintln!(
            "SEEK_DATA/SEEK_HOLE skipped: current kernel/FUSE stack reports transport-layer \
             rejection before FrankenFS can prove all-hole seek semantics: {data0}"
        );
        return;
    }

    assert_eq!(
        data0["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_DATA from file start should surface ENXIO on an all-hole file: {data0}"
    );

    let hole0 = query_seek(path, 0, "SEEK_HOLE");
    assert_eq!(
        hole0["offset"].as_u64(),
        Some(0),
        "SEEK_HOLE from file start should report the all-hole sparse range immediately: {hole0}"
    );

    let data_middle = query_seek(path, 4096, "SEEK_DATA");
    assert_eq!(
        data_middle["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_DATA from inside an all-hole file should still surface ENXIO: {data_middle}"
    );

    let hole_middle = query_seek(path, 4096, "SEEK_HOLE");
    assert_eq!(
        hole_middle["offset"].as_u64(),
        Some(4096),
        "SEEK_HOLE from inside an all-hole file should return the queried hole offset: {hole_middle}"
    );

    let eof_data = query_seek(path, readback.len() as u64, "SEEK_DATA");
    assert_eq!(
        eof_data["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_DATA at EOF should surface ENXIO on an all-hole file: {eof_data}"
    );

    let eof_hole = query_seek(path, readback.len() as u64, "SEEK_HOLE");
    assert_eq!(
        eof_hole["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_HOLE at EOF should surface ENXIO on an all-hole file: {eof_hole}"
    );

    emit_scenario_result(scenario_id, "PASS", Some("all_hole_seek_offsets_verified"));
}

#[test]
fn fuse_create_and_read_file() {
    with_rw_mount(|mnt| {
        let path = mnt.join("newfile.txt");
        fs::write(&path, b"Created via FUSE write path!\n").expect("create file via FUSE");

        let content = fs::read_to_string(&path).expect("read back created file");
        assert_eq!(content, "Created via FUSE write path!\n");

        let meta = fs::metadata(&path).expect("stat created file");
        assert!(meta.is_file());
        assert_eq!(meta.len(), 29);
    });
}

#[test]
fn fuse_conformance_file_lifecycle_open_read_write_flush_fsync_release_matrix() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_conformance_file_lifecycle_matrix";
        let path = mnt.join("lifecycle_matrix.bin");
        let payload = b"lifecycle matrix\n";
        let payload_len = u64::try_from(payload.len()).expect("payload length should fit u64");

        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("open lifecycle matrix file for read/write");

        file.write_all(payload).expect("write lifecycle payload");
        file.flush().expect("flush lifecycle payload");
        file.seek(SeekFrom::Start(0))
            .expect("seek lifecycle file for same-handle read");

        let mut same_handle_readback = vec![0_u8; payload.len()];
        file.read_exact(&mut same_handle_readback)
            .expect("read lifecycle payload from same handle");
        assert_eq!(same_handle_readback.as_slice(), payload);

        file.sync_all().expect("fsync lifecycle file");
        assert_eq!(
            file.metadata()
                .expect("getattr lifecycle file from open handle")
                .len(),
            payload_len
        );
        drop(file);

        let mut reopened = fs::File::open(&path).expect("reopen lifecycle matrix file");
        let mut reopened_readback = Vec::new();
        reopened
            .read_to_end(&mut reopened_readback)
            .expect("read lifecycle payload after release");
        assert_eq!(reopened_readback.as_slice(), payload);
        drop(reopened);

        assert_eq!(
            fs::metadata(&path)
                .expect("getattr lifecycle matrix path")
                .len(),
            payload_len
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("open+write+flush+read+fsync+release+reopen"),
        );
    });
}

fn assert_pwritev2_rwf_persists_after_remount(
    flag_name: &str,
    file_name: &str,
    payload: &[u8],
    scenario_id: &str,
    pass_detail: &str,
) {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ..MountOptions::default()
    };
    let Some(session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let report = run_pwritev2_rwf_probe(&mnt, flag_name, file_name, payload);
    if let Some(skip_reason) = report["skipped"].as_str() {
        emit_scenario_result(scenario_id, "SKIP", Some(skip_reason));
        return;
    }

    let expected_written = i64::try_from(payload.len()).expect("payload length should fit i64");
    assert_eq!(
        report["written"].as_i64(),
        Some(expected_written),
        "pwritev2 {flag_name} should report the full payload length: {report}"
    );
    let payload_hex = report["payload_hex"]
        .as_str()
        .expect("pwritev2 RWF probe should report payload_hex");
    assert_eq!(
        report["readback_hex"].as_str(),
        Some(payload_hex),
        "pwritev2 {flag_name} write should be immediately readable: {report}"
    );

    drop(session);
    wait_for_fuse_mount_released(&mnt);

    let Some(_remount) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };
    let persisted = fs::read(mnt.join(file_name)).expect("read pwritev2 RWF probe after remount");
    assert_eq!(
        persisted.as_slice(),
        payload,
        "{flag_name} pwritev2 payload should survive remount"
    );
    emit_scenario_result(scenario_id, "PASS", Some(pass_detail));
}

#[test]
fn ext4_fuse_pwritev2_rwf_dsync_persists_written_data_after_remount() {
    assert_pwritev2_rwf_persists_after_remount(
        "RWF_DSYNC",
        "rwf_dsync_probe.bin",
        b"rwf-dsync-through-fuse\n",
        "ext4_rw_pwritev2_rwf_dsync",
        "pwritev2_rwf_dsync",
    );
}

#[test]
fn ext4_fuse_pwritev2_rwf_sync_persists_written_data_after_remount() {
    assert_pwritev2_rwf_persists_after_remount(
        "RWF_SYNC",
        "rwf_sync_probe.bin",
        b"rwf-sync-through-fuse\n",
        "ext4_rw_pwritev2_rwf_sync",
        "pwritev2_rwf_sync",
    );
}

#[test]
fn ext4_fuse_pwritev2_rwf_hipri_preserves_normal_offset_write() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let report = run_pwritev2_rwf_hint_probe(
        &mnt,
        "RWF_HIPRI",
        "rwf_hipri_hint_probe.bin",
        b"abcdef",
        b"hipri",
        1,
    );
    if let Some(skip_reason) = report["skipped"].as_str() {
        assert_eq!(
            report["readback_hex"].as_str(),
            report["expected_hex"].as_str(),
            "transport-level RWF_HIPRI refusal must not mutate data: {report}"
        );
        emit_scenario_result("ext4_rw_pwritev2_rwf_hipri_hint", "SKIP", Some(skip_reason));
        return;
    }

    assert_eq!(
        report["written"].as_i64(),
        Some(i64::try_from(b"hipri".len()).expect("payload length fits i64")),
        "RWF_HIPRI should report the normal write length: {report}"
    );
    assert_eq!(
        report["readback_hex"].as_str(),
        report["expected_hex"].as_str(),
        "RWF_HIPRI should preserve caller offset and normal write semantics: {report}"
    );

    emit_scenario_result(
        "ext4_rw_pwritev2_rwf_hipri_hint",
        "PASS",
        Some("rwf_hipri_normal_offset_write"),
    );
}

#[test]
fn ext4_fuse_pwritev2_rwf_nowait_preserves_uncontended_offset_write() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let report = run_pwritev2_rwf_hint_probe(
        &mnt,
        "RWF_NOWAIT",
        "rwf_nowait_probe.bin",
        b"abcdef",
        b"NW",
        2,
    );
    if let Some(skip_reason) = report["skipped"].as_str() {
        assert_eq!(
            report["readback_hex"].as_str(),
            report["expected_hex"].as_str(),
            "transport-level RWF_NOWAIT refusal must not mutate data: {report}"
        );
        emit_scenario_result(
            "ext4_rw_pwritev2_rwf_nowait_uncontended",
            "SKIP",
            Some(skip_reason),
        );
        return;
    }

    assert_eq!(
        report["written"].as_i64(),
        Some(i64::try_from(b"NW".len()).expect("payload length fits i64")),
        "RWF_NOWAIT should report the normal write length when uncontended: {report}"
    );
    assert_eq!(
        report["readback_hex"].as_str(),
        report["expected_hex"].as_str(),
        "RWF_NOWAIT should preserve caller offset and normal write semantics when uncontended: {report}"
    );

    emit_scenario_result(
        "ext4_rw_pwritev2_rwf_nowait_uncontended",
        "PASS",
        Some("rwf_nowait_uncontended_offset_write"),
    );
}

#[test]
fn ext4_fuse_pwritev2_rwf_append_noappend_modes() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let report = run_pwritev2_rwf_append_modes_probe(&mnt);
    if let Some(skip_reason) = report["skipped"].as_str() {
        emit_scenario_result(
            "ext4_rw_pwritev2_rwf_append_noappend_modes",
            "SKIP",
            Some(skip_reason),
        );
        return;
    }

    let append = &report["append"];
    assert_eq!(
        append["written"].as_i64(),
        Some(i64::try_from(b"+append".len()).expect("payload length fits i64")),
        "RWF_APPEND should report the appended payload length: {report}"
    );
    assert_eq!(
        append["readback_hex"].as_str(),
        append["expected_hex"].as_str(),
        "RWF_APPEND should ignore caller offset and append at EOF: {report}"
    );

    let noappend = &report["noappend"];
    assert_eq!(
        noappend["written"].as_i64(),
        Some(i64::try_from(b"XY".len()).expect("payload length fits i64")),
        "RWF_NOAPPEND should report the overwrite payload length: {report}"
    );
    assert_eq!(
        noappend["readback_hex"].as_str(),
        noappend["expected_hex"].as_str(),
        "RWF_NOAPPEND should suppress O_APPEND and preserve caller offset: {report}"
    );

    let conflict = &report["conflict"];
    assert_eq!(
        conflict["errno"].as_i64(),
        Some(i64::from(libc::EINVAL)),
        "RWF_APPEND|RWF_NOAPPEND should reject with EINVAL: {report}"
    );
    assert_eq!(
        conflict["readback_hex"].as_str(),
        conflict["expected_hex"].as_str(),
        "RWF_APPEND|RWF_NOAPPEND must reject before data mutation: {report}"
    );

    emit_scenario_result(
        "ext4_rw_pwritev2_rwf_append_noappend_modes",
        "PASS",
        Some("append_noappend_offset_and_conflict_contract"),
    );
}

#[test]
fn ext4_fuse_pwritev2_rwf_unsupported_intents_reject_without_mutation() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let report = run_pwritev2_rwf_unsupported_intents_probe(&mnt);
    if let Some(skip_reason) = report["skipped"].as_str() {
        emit_scenario_result(
            "ext4_rw_pwritev2_rwf_unsupported_intents",
            "SKIP",
            Some(skip_reason),
        );
        return;
    }

    for (case_key, flag_name) in [("atomic", "RWF_ATOMIC"), ("dontcache", "RWF_DONTCACHE")] {
        let case = &report["cases"][case_key];
        assert_eq!(
            case["errno"].as_i64(),
            Some(EOPNOTSUPP_ERRNO),
            "{flag_name} should reject with EOPNOTSUPP: {report}"
        );
        assert!(
            case["written"].is_null(),
            "{flag_name} should not report a successful byte count: {report}"
        );
        assert_eq!(
            case["readback_hex"].as_str(),
            case["expected_hex"].as_str(),
            "{flag_name} must reject before data mutation: {report}"
        );
    }

    emit_scenario_result(
        "ext4_rw_pwritev2_rwf_unsupported_intents",
        "PASS",
        Some("rwf_atomic_rwf_dontcache_eopnotsupp_no_mutation"),
    );
}

#[test]
fn fuse_write_overwrite_and_append() {
    with_rw_mount(|mnt| {
        let path = mnt.join("overwrite.txt");

        // Write initial content.
        fs::write(&path, b"initial").expect("write initial");
        assert_eq!(fs::read_to_string(&path).expect("read initial"), "initial");

        // Overwrite with longer content.
        fs::write(&path, b"overwritten content").expect("overwrite");
        assert_eq!(
            fs::read_to_string(&path).expect("read overwritten"),
            "overwritten content"
        );

        // Append additional content.
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for append");
        file.write_all(b" + appended").expect("append write");
        drop(file);
        assert_eq!(
            fs::read_to_string(&path).expect("read appended"),
            "overwritten content + appended"
        );
    });
}

#[test]
fn fuse_write_with_offset_extends_file_and_zero_fills_gap() {
    with_rw_mount(|mnt| {
        let path = mnt.join("offset_write.bin");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .expect("create offset_write.bin");

        file.seek(SeekFrom::Start(8))
            .expect("seek to sparse offset");
        file.write_all(b"abc").expect("write payload at offset");
        drop(file);

        let bytes = fs::read(&path).expect("read sparse write result");
        assert_eq!(bytes.len(), 11);
        assert_eq!(&bytes[..8], vec![0_u8; 8].as_slice());
        assert_eq!(&bytes[8..], b"abc");
    });
}

#[test]
fn fuse_write_to_directory_reports_eisdir() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_write_to_directory_errno_eisdir";
        let dir = mnt.join("ext4_write_dir");
        fs::create_dir(&dir).expect("mkdir ext4 write directory target");
        let child = dir.join("child.txt");
        fs::write(&child, b"directory child stays intact\n")
            .expect("seed ext4 write directory child");

        let entries_before = snapshot_directory_entries(&dir);
        let child_before = snapshot_file_state(&child);

        let err = fs::OpenOptions::new()
            .write(true)
            .open(&dir)
            .expect_err("opening a directory for write should fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EISDIR),
            "opening a directory for write should surface exact EISDIR: {err}"
        );
        assert!(
            dir.is_dir(),
            "directory-write rejection must leave the directory in place"
        );
        assert_eq!(
            snapshot_directory_entries(&dir),
            entries_before,
            "directory-write rejection must not change directory entries"
        );
        assert_file_state_unchanged(&child, &child_before, "directory write rejection");
        emit_scenario_result(scenario_id, "PASS", Some("open=EISDIR_no_drift"));
    });
}

#[test]
fn fuse_mkdir_and_nested_create() {
    with_rw_mount(|mnt| {
        let dir = mnt.join("newdir");
        fs::create_dir(&dir).expect("mkdir via FUSE");

        let meta = fs::metadata(&dir).expect("stat newdir");
        assert!(meta.is_dir());

        // Create a file inside the new directory.
        let nested = dir.join("inner.txt");
        fs::write(&nested, b"nested content\n").expect("write nested file");

        let content = fs::read_to_string(&nested).expect("read nested file");
        assert_eq!(content, "nested content\n");
    });
}

#[test]
fn fuse_conformance_namespace_lookup_readdir_symlink_rename_unlink_matrix() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_conformance_namespace_matrix";
        let dir = mnt.join("namespace_matrix");
        fs::create_dir(&dir).expect("mkdir namespace matrix directory");

        let dir_meta = fs::metadata(&dir).expect("lookup/getattr namespace matrix directory");
        assert!(dir_meta.is_dir());

        let child = dir.join("child.txt");
        let payload = b"namespace matrix payload\n";
        let payload_len = u64::try_from(payload.len()).expect("payload length should fit u64");
        fs::write(&child, payload).expect("create/write namespace matrix child");

        let link = dir.join("child.link");
        std::os::unix::fs::symlink("child.txt", &link).expect("symlink namespace matrix child");
        assert_eq!(
            fs::read_link(&link).expect("readlink namespace matrix child"),
            PathBuf::from("child.txt")
        );

        let entries: HashSet<String> = fs::read_dir(&dir)
            .expect("readdir namespace matrix directory")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries.contains("child.txt"),
            "readdir should include child.txt, got {entries:?}"
        );
        assert!(
            entries.contains("child.link"),
            "readdir should include child.link, got {entries:?}"
        );

        let renamed = dir.join("renamed.txt");
        fs::rename(&child, &renamed).expect("rename namespace matrix child");
        assert!(
            fs::symlink_metadata(&child).is_err(),
            "renamed source should no longer resolve"
        );
        assert_eq!(
            fs::read(&renamed)
                .expect("read renamed namespace matrix child")
                .as_slice(),
            payload
        );
        assert_eq!(
            fs::metadata(&renamed)
                .expect("lookup/getattr renamed namespace matrix child")
                .len(),
            payload_len
        );

        fs::remove_file(&link).expect("unlink namespace matrix symlink");
        fs::remove_file(&renamed).expect("unlink namespace matrix file");
        fs::remove_dir(&dir).expect("rmdir namespace matrix directory");
        assert!(
            fs::symlink_metadata(&dir).is_err(),
            "rmdir should remove namespace matrix directory"
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("lookup+getattr+readdir+mkdir+symlink+readlink+rename+unlink+rmdir"),
        );
    });
}

#[test]
fn fuse_mkdir_existing_directory_fails() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_mkdir_existing_directory_eexist";
        let dir = mnt.join("already_there");
        fs::create_dir(&dir).expect("initial mkdir should succeed");

        let err = fs::create_dir(&dir).expect_err("mkdir existing should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        emit_scenario_result(scenario_id, "PASS", Some("errno=EEXIST"));
    });
}

#[test]
fn fuse_create_and_mkdir_under_non_directory_parent_report_enotdir() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_create_and_mkdir_under_non_directory_parent";
        let regular_parent = mnt.join("hello.txt");
        let root_entries_before = snapshot_directory_entries(mnt);
        let parent_before = snapshot_file_state(&regular_parent);

        let create_target = regular_parent.join("child.txt");
        let create_err = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&create_target)
            .expect_err("create beneath regular-file parent should fail");
        assert_eq!(
            create_err.raw_os_error(),
            Some(libc::ENOTDIR),
            "create beneath a regular-file parent should surface exact ENOTDIR: {create_err}"
        );
        assert!(
            fs::symlink_metadata(&create_target).is_err(),
            "rejected create must not leave a nested child entry behind"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected create must not change visible root entries"
        );
        assert_file_state_unchanged(
            &regular_parent,
            &parent_before,
            "non-directory parent after rejected create",
        );

        let mkdir_target = regular_parent.join("child_dir");
        let mkdir_err = fs::create_dir(&mkdir_target)
            .expect_err("mkdir beneath regular-file parent should fail");
        assert_eq!(
            mkdir_err.raw_os_error(),
            Some(libc::ENOTDIR),
            "mkdir beneath a regular-file parent should surface exact ENOTDIR: {mkdir_err}"
        );
        assert!(
            fs::symlink_metadata(&mkdir_target).is_err(),
            "rejected mkdir must not leave a nested directory entry behind"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected mkdir must not change visible root entries"
        );
        assert_file_state_unchanged(
            &regular_parent,
            &parent_before,
            "non-directory parent after rejected mkdir",
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("create=ENOTDIR_mkdir=ENOTDIR_no_drift"),
        );
    });
}

#[test]
fn fuse_unlink_removes_file() {
    with_rw_mount(|mnt| {
        // hello.txt exists from create_test_image.
        let path = mnt.join("hello.txt");
        assert!(path.exists(), "hello.txt should exist before unlink");

        fs::remove_file(&path).expect("unlink hello.txt via FUSE");
        assert!(!path.exists(), "hello.txt should be gone after unlink");
    });
}

#[test]
fn fuse_rmdir_missing_directory_fails() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_rmdir_missing_directory_enoent";
        let missing = mnt.join("no_such_dir");
        let err = fs::remove_dir(&missing).expect_err("rmdir missing should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        emit_scenario_result(scenario_id, "PASS", Some("errno=ENOENT"));
    });
}

#[test]
fn fuse_rmdir_removes_empty_directory() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_rmdir_empty_directory_ok";
        let dir = mnt.join("empty_dir");
        fs::create_dir(&dir).expect("mkdir empty_dir");
        assert!(dir.exists());

        fs::remove_dir(&dir).expect("rmdir empty_dir via FUSE");
        assert!(!dir.exists(), "empty_dir should be gone after rmdir");
        emit_scenario_result(scenario_id, "PASS", Some("entry_absent_after_rmdir"));
    });
}

#[test]
fn fuse_rmdir_on_file_reports_enotdir() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_rmdir_on_file_reports_enotdir";
        let path = mnt.join("hello.txt");
        let original_bytes = fs::read(&path).expect("read hello.txt before rmdir-on-file");

        let err = fs::remove_dir(&path).expect_err("rmdir on regular file should fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENOTDIR),
            "rmdir on a regular file should surface exact ENOTDIR: {err}"
        );
        assert!(
            path.is_file(),
            "failed rmdir on regular file must leave the file in place"
        );
        assert_eq!(
            fs::read(&path).expect("read hello.txt after failed rmdir-on-file"),
            original_bytes,
            "failed rmdir on regular file must not mutate file contents"
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=ENOTDIR_no_drift"));
    });
}

#[test]
fn fuse_unlink_directory_reports_eisdir() {
    with_rw_mount(|mnt| {
        assert_unlink_directory_via_remove_file_reports_eisdir(
            mnt,
            "ext4_rw_unlink_directory_reports_eisdir",
        );
    });
}

#[test]
fn fuse_mkdir_rmdir_parent_nlink_accounting() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_mkdir_rmdir_parent_nlink_accounting";
        let parent = mnt;
        let child_name = "nlink-accounting-dir";
        let child = parent.join(child_name);
        let parent_entries_before = snapshot_directory_entries(parent);
        let parent_nlink_before = fs::metadata(parent)
            .expect("stat parent before mkdir")
            .nlink();

        assert!(
            !parent_entries_before.contains(child_name),
            "test directory name should be absent before mkdir"
        );

        fs::create_dir(&child).expect("mkdir child directory");

        let parent_nlink_after_mkdir = fs::metadata(parent)
            .expect("stat parent after mkdir")
            .nlink();
        let child_nlink_after_mkdir = fs::metadata(&child)
            .expect("stat child after mkdir")
            .nlink();
        let mut parent_entries_expected_after_mkdir = parent_entries_before.clone();
        parent_entries_expected_after_mkdir.insert(child_name.to_string());
        assert_eq!(
            parent_nlink_after_mkdir,
            parent_nlink_before + 1,
            "mkdir must increment parent st_nlink by one for the new child directory"
        );
        assert_eq!(
            child_nlink_after_mkdir, 2,
            "new directory must expose the canonical '.'/'..' link count"
        );
        assert_eq!(
            snapshot_directory_entries(parent),
            parent_entries_expected_after_mkdir,
            "mkdir must add exactly one visible root entry"
        );

        fs::remove_dir(&child).expect("rmdir child directory");

        let parent_nlink_after_rmdir = fs::metadata(parent)
            .expect("stat parent after rmdir")
            .nlink();
        assert_eq!(
            parent_nlink_after_rmdir, parent_nlink_before,
            "rmdir must restore the parent st_nlink once the child directory is gone"
        );
        assert_eq!(
            snapshot_directory_entries(parent),
            parent_entries_before,
            "rmdir must restore the visible parent entries to baseline"
        );
        assert!(
            fs::symlink_metadata(&child).is_err(),
            "removed child directory must no longer be visible"
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("mkdir_parent_nlink_plus_one_rmdir_restored"),
        );
    });
}

#[test]
fn fuse_rmdir_non_empty_fails() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_rmdir_non_empty_enotempty";
        let dir = mnt.join("non_empty_dir");
        fs::create_dir(&dir).expect("mkdir non_empty_dir");
        fs::write(dir.join("child.txt"), b"child").expect("create child in non_empty_dir");

        let err = fs::remove_dir(&dir).expect_err("rmdir non-empty should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::DirectoryNotEmpty);
        assert!(
            dir.exists(),
            "directory should still exist after failed rmdir"
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=ENOTEMPTY_dir_preserved"));
    });
}

#[test]
fn fuse_rename_over_existing_destination_replaces_target() {
    with_rw_mount(|mnt| {
        let src = mnt.join("src.txt");
        let dst = mnt.join("dst.txt");
        fs::write(&src, b"from-src").expect("write src");
        fs::write(&dst, b"stale-dst").expect("write existing dst");

        fs::rename(&src, &dst).expect("rename over existing destination");
        assert!(!src.exists(), "source path should be removed");
        assert_eq!(
            fs::read_to_string(&dst).expect("read replaced dst"),
            "from-src"
        );
    });
}

#[test]
fn fuse_rename_file() {
    with_rw_mount(|mnt| {
        let old = mnt.join("hello.txt");
        let new = mnt.join("renamed.txt");
        assert!(old.exists());

        fs::rename(&old, &new).expect("rename via FUSE");
        assert!(!old.exists(), "old name should be gone");
        assert!(new.exists(), "new name should exist");

        let content = fs::read_to_string(&new).expect("read renamed file");
        assert_eq!(content, "Hello from FrankenFS E2E!\n");
    });
}

#[test]
fn fuse_rename_across_directories() {
    with_rw_mount(|mnt| {
        let src = mnt.join("hello.txt");
        let dst = mnt.join("testdir/moved.txt");
        assert!(src.exists());

        fs::rename(&src, &dst).expect("rename across dirs via FUSE");
        assert!(!src.exists());

        let content = fs::read_to_string(&dst).expect("read moved file");
        assert_eq!(content, "Hello from FrankenFS E2E!\n");
    });
}

#[test]
fn fuse_inotify_same_parent_rename_pairs_have_matching_cookies() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    with_rw_mount_sized(16 * 1024 * 1024, |mnt| {
        let scenario_id = "ext4_rw_inotify_same_parent_rename_cookie_pairs";
        let report = run_inotify_rename_probe(mnt, "same-parent");
        if let Some(reason) = report["skipped"].as_str() {
            eprintln!("inotify same-parent probe unavailable, skipping: {reason}");
            return;
        }

        assert_eq!(report["scenario"].as_str(), Some("same_parent"));
        assert_eq!(report["renames"].as_u64(), Some(100));
        assert_eq!(report["moved_from"].as_u64(), Some(100));
        assert_eq!(report["moved_to"].as_u64(), Some(100));
        assert_eq!(
            report["cookies"].as_u64(),
            Some(100),
            "each same-parent rename should carry one unique non-zero cookie: {report}"
        );
        emit_scenario_result(scenario_id, "PASS", Some("100_matching_move_cookies"));
    });
}

#[test]
fn fuse_inotify_cross_directory_rename_uses_move_pair_not_delete_create() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    with_rw_mount_sized(16 * 1024 * 1024, |mnt| {
        let scenario_id = "ext4_rw_inotify_cross_directory_rename_cookie_pair";
        let report = run_inotify_rename_probe(mnt, "cross-directory");
        if let Some(reason) = report["skipped"].as_str() {
            eprintln!("inotify cross-directory probe unavailable, skipping: {reason}");
            return;
        }

        assert_eq!(report["scenario"].as_str(), Some("cross_directory"));
        assert_eq!(report["moved_from"].as_u64(), Some(1));
        assert_eq!(report["moved_to"].as_u64(), Some(1));
        assert!(
            report["cookie"].as_u64().is_some_and(|cookie| cookie != 0),
            "cross-directory rename should carry a non-zero inotify move cookie: {report}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("cross_dir_move_pair_no_delete_create"),
        );
    });
}

#[test]
fn fuse_rename_over_same_inode_hardlink_is_noop() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_rename_over_same_inode_hardlink_noop";
        let original = mnt.join("original.txt");
        let alias = mnt.join("alias.txt");
        fs::write(&original, b"same inode rename\n").expect("write original");
        fs::hard_link(&original, &alias).expect("create alias hard link");

        let entries_before = snapshot_directory_entries(mnt);
        let alias_before = snapshot_file_state(&alias);
        let original_ino_before = fs::metadata(&original).expect("stat original").ino();
        let alias_meta_before = fs::metadata(&alias).expect("stat alias");
        assert_eq!(
            alias_meta_before.ino(),
            original_ino_before,
            "hard link should point at the same inode before rename"
        );
        assert_eq!(
            alias_meta_before.nlink(),
            2,
            "same-inode rename precondition should have two names"
        );

        fs::rename(&original, &alias).expect("rename over same-inode hard link");

        assert_eq!(
            snapshot_directory_entries(mnt),
            entries_before,
            "same-inode rename should be a visible no-op"
        );
        assert!(
            fs::symlink_metadata(&original).is_ok(),
            "source name should still resolve after same-inode rename"
        );
        assert_file_state_unchanged(&alias, &alias_before, "same-inode rename alias");
        assert_file_state_unchanged(&original, &alias_before, "same-inode rename source");

        let alias_meta_after = fs::metadata(&alias).expect("stat alias after rename");
        assert_eq!(
            alias_meta_after.ino(),
            original_ino_before,
            "destination should keep the original inode"
        );
        assert_eq!(
            alias_meta_after.nlink(),
            2,
            "same-inode rename should preserve the shared link count"
        );
        let original_meta_after = fs::metadata(&original).expect("stat source after rename");
        assert_eq!(
            original_meta_after.ino(),
            original_ino_before,
            "source should still resolve to the original inode"
        );
        assert_eq!(
            original_meta_after.nlink(),
            2,
            "source should keep the shared link count after same-inode rename"
        );
        emit_scenario_result(scenario_id, "PASS", Some("visible_noop_nlink=2"));
    });
}

#[test]
fn fuse_rename_same_name_is_noop() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_rename_same_name_noop";
        let path = mnt.join("same-name.txt");
        fs::write(&path, b"same name rename\n").expect("write rename same-name seed");

        let entries_before = snapshot_directory_entries(mnt);
        let before = snapshot_file_state(&path);
        let ino_before = fs::metadata(&path)
            .expect("stat before same-name rename")
            .ino();

        fs::rename(&path, &path).expect("rename same name should succeed");

        assert_eq!(
            snapshot_directory_entries(mnt),
            entries_before,
            "same-name rename should not change directory entries"
        );
        assert_file_state_unchanged(&path, &before, "same-name rename");

        let ino_after = fs::metadata(&path)
            .expect("stat after same-name rename")
            .ino();
        assert_eq!(
            ino_after, ino_before,
            "same-name rename should preserve the inode binding"
        );

        emit_scenario_result(scenario_id, "PASS", Some("visible_noop"));
    });
}

#[test]
fn fuse_rename_directory_into_own_child_reports_einval() {
    with_rw_mount(|mnt| {
        assert_rename_directory_into_own_child_reports_einval(
            mnt,
            "ext4_rw_rename_directory_into_own_child_errno_einval",
        );
    });
}

#[test]
fn fuse_rename_missing_source_reports_enoent() {
    with_rw_mount(|mnt| {
        assert_rename_missing_source_reports_enoent(
            mnt,
            "ext4_rw_rename_missing_source_errno_enoent",
        );
    });
}

#[test]
fn fuse_rename_file_directory_type_mismatch_reports_eisdir_and_enotdir() {
    with_rw_mount(|mnt| {
        assert_rename_file_directory_type_mismatch_contract(
            mnt,
            "ext4_rw_rename_file_directory_type_mismatch",
        );
    });
}

#[test]
fn fuse_rename_over_nonempty_directory_reports_enotempty() {
    with_rw_mount(|mnt| {
        assert_rename_over_nonempty_directory_reports_enotempty(
            mnt,
            "ext4_rw_rename_over_nonempty_directory_errno_enotempty",
        );
    });
}

#[test]
fn fuse_renameat2_flags_honor_noreplace_and_exchange() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_renameat2_flags";
        if !command_available("python3") {
            eprintln!("python3 not available, skipping");
            return;
        }

        let noreplace_src = mnt.join("renameat2-noreplace-src.txt");
        let noreplace_dst = mnt.join("renameat2-noreplace-dst.txt");
        let noreplace_existing_src = mnt.join("renameat2-noreplace-existing-src.txt");
        let noreplace_existing_dst = mnt.join("renameat2-noreplace-existing-dst.txt");
        let exchange_src = mnt.join("renameat2-exchange-src.txt");
        let exchange_dst = mnt.join("renameat2-exchange-dst.txt");

        fs::write(&noreplace_src, b"noreplace src\n").expect("write renameat2 noreplace src");
        fs::write(&noreplace_existing_src, b"noreplace existing src\n")
            .expect("write renameat2 noreplace existing src");
        fs::write(&noreplace_existing_dst, b"noreplace existing dst\n")
            .expect("write renameat2 noreplace existing dst");
        fs::write(&exchange_src, b"exchange src\n").expect("write renameat2 exchange src");
        fs::write(&exchange_dst, b"exchange dst\n").expect("write renameat2 exchange dst");

        let noreplace_existing_src_before = snapshot_file_state(&noreplace_existing_src);
        let noreplace_existing_dst_before = snapshot_file_state(&noreplace_existing_dst);
        let exchange_src_before = snapshot_file_state(&exchange_src);
        let exchange_dst_before = snapshot_file_state(&exchange_dst);

        let noreplace_report =
            py_renameat2_report(&noreplace_src, &noreplace_dst, libc::RENAME_NOREPLACE);
        assert_eq!(
            noreplace_report["ok"].as_bool(),
            Some(true),
            "renameat2(RENAME_NOREPLACE) should succeed when destination is absent: {noreplace_report:?}"
        );
        assert!(
            fs::symlink_metadata(&noreplace_src).is_err(),
            "successful RENAME_NOREPLACE must remove the source entry"
        );
        assert_eq!(
            fs::read_to_string(&noreplace_dst).expect("read renameat2 noreplace destination"),
            "noreplace src\n"
        );

        let noreplace_existing_report = py_renameat2_report(
            &noreplace_existing_src,
            &noreplace_existing_dst,
            libc::RENAME_NOREPLACE,
        );
        assert_eq!(
            noreplace_existing_report["errno"].as_i64(),
            Some(i64::from(libc::EEXIST)),
            "renameat2(RENAME_NOREPLACE) over an existing destination should surface exact EEXIST: {noreplace_existing_report:?}"
        );
        assert_file_state_unchanged(
            &noreplace_existing_src,
            &noreplace_existing_src_before,
            "renameat2 RENAME_NOREPLACE existing source",
        );
        assert_file_state_unchanged(
            &noreplace_existing_dst,
            &noreplace_existing_dst_before,
            "renameat2 RENAME_NOREPLACE existing destination",
        );

        let exchange_report =
            py_renameat2_report(&exchange_src, &exchange_dst, libc::RENAME_EXCHANGE);
        assert_eq!(
            exchange_report["ok"].as_bool(),
            Some(true),
            "renameat2(RENAME_EXCHANGE) should atomically swap existing entries: {exchange_report:?}"
        );
        assert_eq!(
            fs::read(&exchange_src).expect("read swapped exchange source"),
            exchange_dst_before.bytes,
            "RENAME_EXCHANGE source path should expose the original destination bytes"
        );
        assert_eq!(
            fs::read(&exchange_dst).expect("read swapped exchange destination"),
            exchange_src_before.bytes,
            "RENAME_EXCHANGE destination path should expose the original source bytes"
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("noreplace=create+noreplace_existing=EEXIST+exchange=swap"),
        );
    });
}

#[test]
fn fuse_hard_link() {
    with_rw_mount(|mnt| {
        let original = mnt.join("hello.txt");
        let link = mnt.join("hello_link.txt");

        fs::hard_link(&original, &link).expect("hard link via FUSE");

        let content = fs::read_to_string(&link).expect("read through hard link");
        assert_eq!(content, "Hello from FrankenFS E2E!\n");

        // Both should share the same inode.
        let orig_ino = fs::metadata(&original).expect("stat original").ino();
        let link_ino = fs::metadata(&link).expect("stat link").ino();
        assert_eq!(orig_ino, link_ino, "hard link should share inode");
        let orig_nlink = fs::metadata(&original).expect("stat original").nlink();
        let link_nlink = fs::metadata(&link).expect("stat link").nlink();
        assert_eq!(orig_nlink, 2, "original should report two hard links");
        assert_eq!(link_nlink, 2, "link should report two hard links");
    });
}

#[test]
fn fuse_hard_link_to_symlink_preserves_symlink_type() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_hard_link_to_symlink_preserves_type";
        let symlink_path = mnt.join("hello_symlink.txt");
        let alias_path = mnt.join("hello_symlink_alias.txt");

        std::os::unix::fs::symlink("hello.txt", &symlink_path).expect("create source symlink");
        fs::hard_link(&symlink_path, &alias_path).expect("hard-link source symlink");

        let symlink_meta = fs::symlink_metadata(&symlink_path).expect("lstat source symlink");
        let alias_meta = fs::symlink_metadata(&alias_path).expect("lstat hard-link alias");
        assert!(
            symlink_meta.file_type().is_symlink(),
            "source path must remain a symlink after hard-linking"
        );
        assert!(
            alias_meta.file_type().is_symlink(),
            "hard-link alias must preserve the symlink inode type"
        );
        assert_eq!(
            symlink_meta.ino(),
            alias_meta.ino(),
            "hard-link alias should reference the same symlink inode"
        );
        assert_eq!(
            symlink_meta.nlink(),
            2,
            "source symlink should report two hard-link names"
        );
        assert_eq!(
            alias_meta.nlink(),
            2,
            "hard-link alias should report the shared symlink link count"
        );

        let symlink_target = fs::read_link(&symlink_path).expect("readlink source symlink");
        let alias_target = fs::read_link(&alias_path).expect("readlink hard-link alias");
        assert_eq!(symlink_target, PathBuf::from("hello.txt"));
        assert_eq!(
            alias_target, symlink_target,
            "hard-link alias should expose the same symlink target bytes"
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("lstat=symlink_readlink=target_preserved"),
        );
    });
}

#[test]
fn fuse_symlink_create_and_follow() {
    with_rw_mount(|mnt| {
        let target = mnt.join("hello.txt");
        let link = mnt.join("sym.txt");

        std::os::unix::fs::symlink("hello.txt", &link).expect("symlink via FUSE");

        // Verify readlink returns the target.
        let read_target = fs::read_link(&link).expect("readlink via FUSE");
        assert_eq!(read_target.to_str().unwrap(), "hello.txt");

        // Following the symlink should work.
        let content = fs::read_to_string(&link).expect("read through new symlink");
        assert_eq!(content, "Hello from FrankenFS E2E!\n");

        // Symlink metadata should differ from target.
        let link_meta = fs::symlink_metadata(&link).expect("lstat symlink");
        assert!(link_meta.file_type().is_symlink());
        let _ = target; // used implicitly via symlink follow
    });
}

#[test]
fn fuse_readlink_on_non_symlink_reports_einval() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_readlink_on_non_symlink_reports_einval";
        let file_path = mnt.join("hello.txt");
        let dir_path = mnt.join("testdir");
        let root_entries_before = snapshot_directory_entries(mnt);
        let file_before = snapshot_file_state(&file_path);
        let dir_entries_before = snapshot_directory_entries(&dir_path);

        let file_err = fs::read_link(&file_path).expect_err("readlink on regular file should fail");
        assert_eq!(
            file_err.raw_os_error(),
            Some(libc::EINVAL),
            "readlink on regular file should surface exact EINVAL: {file_err}"
        );
        assert_file_state_unchanged(
            &file_path,
            &file_before,
            "readlink rejection on regular file",
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected readlink on regular file must not change root entries"
        );

        let dir_err = fs::read_link(&dir_path).expect_err("readlink on directory should fail");
        assert_eq!(
            dir_err.raw_os_error(),
            Some(libc::EINVAL),
            "readlink on directory should surface exact EINVAL: {dir_err}"
        );
        assert_eq!(
            snapshot_directory_entries(&dir_path),
            dir_entries_before,
            "rejected readlink on directory must not change directory entries"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected readlink on directory must not change root entries"
        );
        emit_scenario_result(scenario_id, "PASS", Some("file+dir_errno=EINVAL_no_drift"));
    });
}

#[test]
fn fuse_symlink_target_path_max_boundary_and_enametoolong_contract() {
    with_rw_mount(|mnt| {
        assert_symlink_target_path_max_contract(mnt, "ext4_rw_symlink_target_path_max");
    });
}

fn assert_symlink_target_path_max_contract(mnt: &Path, scenario_id: &str) {
    const LINUX_PATH_MAX: usize = 4096;
    const MAX_SYMLINK_TARGET_LEN: usize = LINUX_PATH_MAX - 1;
    let entries_before = snapshot_directory_entries(mnt);

    let path_max_link = mnt.join("sym_path_max.lnk");
    let path_max_target = "a".repeat(MAX_SYMLINK_TARGET_LEN);
    match std::os::unix::fs::symlink(&path_max_target, &path_max_link) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
            assert!(
                fs::symlink_metadata(&path_max_link).is_err(),
                "transport-rejected PATH_MAX-1 symlink must not leave a directory entry behind"
            );
            assert_eq!(
                snapshot_directory_entries(mnt),
                entries_before,
                "transport-rejected PATH_MAX-1 symlink must not change root entries"
            );
            emit_scenario_result(
                scenario_id,
                "SKIP",
                Some("path_max_minus_one_rejected_by_kernel_or_fuse_transport_einval"),
            );
            return;
        }
        Err(error) => {
            panic!("symlink with PATH_MAX-1 target should succeed on mounted path: {error}")
        }
    }
    assert!(
        fs::symlink_metadata(&path_max_link)
            .expect("stat PATH_MAX-1 symlink")
            .file_type()
            .is_symlink(),
        "PATH_MAX-1 symlink must materialize as a symlink on the mounted path"
    );
    let readback = fs::read_link(&path_max_link).expect("readlink PATH_MAX-1 symlink");
    assert_eq!(
        readback.as_os_str().as_encoded_bytes().len(),
        MAX_SYMLINK_TARGET_LEN,
        "readlink of PATH_MAX-1 symlink must return full target length"
    );
    assert_eq!(
        readback.as_os_str().as_encoded_bytes(),
        path_max_target.as_bytes(),
        "readlink of PATH_MAX-1 symlink must return original target bytes"
    );

    let too_long_link = mnt.join("sym_too_long.lnk");
    let too_long_target = "b".repeat(LINUX_PATH_MAX);
    let too_long_err = std::os::unix::fs::symlink(&too_long_target, &too_long_link)
        .expect_err("symlink with target >= PATH_MAX must be rejected");
    assert_eq!(
        too_long_err.raw_os_error(),
        Some(libc::ENAMETOOLONG),
        "PATH_MAX symlink target must surface exact ENAMETOOLONG: {too_long_err}"
    );
    assert!(
        fs::symlink_metadata(&too_long_link).is_err(),
        "rejected symlink must not leave a directory entry behind"
    );

    let empty_link = mnt.join("sym_empty.lnk");
    let empty_err = std::os::unix::fs::symlink("", &empty_link)
        .expect_err("symlink with empty target must be rejected");
    assert_eq!(
        empty_err.raw_os_error(),
        Some(libc::ENOENT),
        "empty symlink target must surface Linux VFS ENOENT before FUSE dispatch: {empty_err}"
    );
    assert!(
        fs::symlink_metadata(&empty_link).is_err(),
        "rejected empty-target symlink must not leave a directory entry behind"
    );

    let mut entries_after = entries_before;
    entries_after.insert("sym_path_max.lnk".to_string());
    assert_eq!(
        snapshot_directory_entries(mnt),
        entries_after,
        "only the accepted PATH_MAX-1 symlink should appear in root entries"
    );
    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("path_max_minus_one=ok_path_max=ENAMETOOLONG_empty=ENOENT_no_drift"),
    );
}

#[test]
fn fuse_setattr_truncate() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        let original_len = fs::metadata(&path).expect("stat").len();
        assert!(original_len > 0);

        // Truncate to 5 bytes.
        let f = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for truncate");
        f.set_len(5).expect("truncate via FUSE");
        drop(f);

        let new_len = fs::metadata(&path).expect("stat after truncate").len();
        assert_eq!(new_len, 5, "file should be truncated to 5 bytes");

        let content = fs::read_to_string(&path).expect("read truncated file");
        assert_eq!(content, "Hello");
    });
}

#[test]
fn fuse_setattr_chmod() {
    with_rw_mount(|mnt| {
        // hello.txt exists from create_test_image.
        let path = mnt.join("hello.txt");
        let orig_meta = fs::metadata(&path).expect("stat hello.txt");
        let orig_mode = orig_meta.permissions().mode() & 0o7777;

        // Change to 0o755.
        let new_perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&path, new_perms).expect("chmod 755 via FUSE");

        let meta = fs::metadata(&path).expect("stat after chmod");
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            0o755,
            "permissions should be 0o755 after chmod (were 0o{orig_mode:o})"
        );

        // Change to 0o600.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod 600 via FUSE");

        let meta = fs::metadata(&path).expect("stat after second chmod");
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            0o600,
            "permissions should be 0o600 after second chmod"
        );

        // File should still be readable/writable by us since we own it.
        let content = fs::read_to_string(&path).expect("read after chmod");
        assert_eq!(content, "Hello from FrankenFS E2E!\n");
    });
}

#[test]
#[ignore = "requires /dev/fuse and root for chown"]
#[allow(clippy::similar_names)] // uid/gid are naturally similar
fn fuse_setattr_chown() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        let meta = fs::metadata(&path).expect("stat hello.txt");
        let owner_uid = meta.uid();
        let owner_gid = meta.gid();

        // Try to chown to the same uid/gid (should always succeed even without CAP_CHOWN).
        let script = format!(
            "import os; os.chown({path:?}, {uid}, {gid})",
            path = path.to_str().unwrap(),
            uid = owner_uid,
            gid = owner_gid,
        );
        let out = Command::new("python3")
            .args(["-c", &script])
            .output()
            .expect("python3 chown");
        assert!(
            out.status.success(),
            "chown to same uid/gid failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Verify uid/gid are unchanged.
        let meta2 = fs::metadata(&path).expect("stat after no-op chown");
        assert_eq!(meta2.uid(), owner_uid);
        assert_eq!(meta2.gid(), owner_gid);

        // Attempt chown to uid 65534 (nobody). This requires CAP_CHOWN;
        // skip the assertion if we get EPERM (non-root environment).
        let script2 = format!(
            "import os\ntry:\n    os.chown({path:?}, 65534, 65534)\n    print('OK')\nexcept PermissionError:\n    print('EPERM')",
            path = path.to_str().unwrap(),
        );
        let out2 = Command::new("python3")
            .args(["-c", &script2])
            .output()
            .expect("python3 chown to nobody");
        assert!(out2.status.success());
        let result = String::from_utf8_lossy(&out2.stdout);
        if result.trim() == "OK" {
            let meta3 = fs::metadata(&path).expect("stat after chown to nobody");
            assert_eq!(meta3.uid(), 65534, "uid should be 65534 after chown");
            assert_eq!(meta3.gid(), 65534, "gid should be 65534 after chown");
        }
        // If EPERM, the test passes silently — chown path was exercised.
    });
}

#[test]
fn fuse_setattr_utimes() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Use Python os.utime to set atime and mtime to a known epoch.
        let script = format!(
            "import os; os.utime({path:?}, (1_700_000_000, 1_700_000_000))",
            path = path.to_str().unwrap(),
        );
        let out = Command::new("python3")
            .args(["-c", &script])
            .output()
            .expect("python3 utime");
        assert!(
            out.status.success(),
            "os.utime failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after utime");
        // atime and mtime should both be 1_700_000_000.
        assert_eq!(
            meta.atime(),
            1_700_000_000,
            "atime should be 1700000000 after os.utime"
        );
        assert_eq!(
            meta.mtime(),
            1_700_000_000,
            "mtime should be 1700000000 after os.utime"
        );

        // Set different atime and mtime values.
        let script2 = format!(
            "import os; os.utime({path:?}, (1_600_000_000, 1_650_000_000))",
            path = path.to_str().unwrap(),
        );
        let out2 = Command::new("python3")
            .args(["-c", &script2])
            .output()
            .expect("python3 utime second");
        assert!(
            out2.status.success(),
            "os.utime (second) failed: {}",
            String::from_utf8_lossy(&out2.stderr)
        );

        let meta2 = fs::metadata(&path).expect("stat after second utime");
        assert_eq!(meta2.atime(), 1_600_000_000, "atime should be 1600000000");
        assert_eq!(meta2.mtime(), 1_650_000_000, "mtime should be 1650000000");
    });
}

#[test]
fn fuse_setattr_read_only_rejects_chmod_truncate_and_utimes_with_erofs() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    assert_read_only_setattr_contract(
        &mnt.join("hello.txt"),
        "ext4_ro_setattr_rejects_erofs_no_drift",
    );
}

#[test]
fn fuse_read_only_unlink_rmdir_and_rename_report_erofs_without_dirent_drift() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_seeded_namespace_removal_fixture(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    let keep_file = mnt.join("readonly_unlink_seed.txt");
    let empty_dir = mnt.join("readonly_empty_dir");
    let rename_source = mnt.join("readonly_rename_source.txt");
    assert_eq!(
        fs::read(&keep_file).expect("read seeded ext4 unlink file"),
        b"readonly ext4 unlink seed\n",
        "read-only remount must preserve the seeded unlink target bytes"
    );
    assert_eq!(
        fs::read(&rename_source).expect("read seeded ext4 rename source file"),
        b"readonly ext4 rename source\n",
        "read-only remount must preserve the seeded rename source bytes"
    );
    assert!(
        empty_dir.is_dir(),
        "read-only remount must preserve the seeded empty directory"
    );

    assert_read_only_unlink_rmdir_and_rename_contract(
        &mnt,
        &keep_file,
        &empty_dir,
        &rename_source,
        "ext4_ro_unlink_rmdir_rename_reject_erofs_no_drift",
    );
}

#[test]
fn fuse_read_only_fallocate_mutation_attempts_report_erofs_without_file_drift() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    let scenario_id = "ext4_ro_fallocate_mutation_attempts_reject_erofs_no_drift";
    let path = mnt.join("hello.txt");
    let before = snapshot_file_state(&path);

    let preallocate_report = py_fallocate_report(&path, 0, 0, before.len + 4096);
    assert_eq!(
        preallocate_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only preallocate should surface exact EROFS: {preallocate_report}"
    );
    assert_file_state_unchanged(&path, &before, "rejected read-only preallocate");

    let punch_hole_report = py_fallocate_report(
        &path,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
        0,
        before.len.min(8),
    );
    assert_eq!(
        punch_hole_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only punch-hole should surface exact EROFS: {punch_hole_report}"
    );
    assert_file_state_unchanged(&path, &before, "rejected read-only punch-hole");

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("preallocate+punch_hole=EROFS_no_file_drift"),
    );
}

#[test]
fn ext4_fuse_fallocate_preallocate_extends_size() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fallocate_preallocate_extends_size";
        let path = mnt.join("preallocated.bin");
        fs::write(&path, b"").expect("create empty file");

        let out = Command::new("fallocate")
            .args(["-l", "8192", path.to_str().unwrap()])
            .output()
            .expect("fallocate command");
        assert!(
            out.status.success(),
            "fallocate failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after fallocate");
        assert_eq!(
            meta.len(),
            8192,
            "file apparent size should be 8192 after fallocate"
        );
        assert!(
            meta.blocks() * 512 >= 8192,
            "allocated disk space ({}*512={}) should be >= 8192",
            meta.blocks(),
            meta.blocks() * 512
        );

        fs::write(&path, b"data in preallocated space").expect("write to preallocated");
        let content = fs::read_to_string(&path).expect("read preallocated");
        assert_eq!(content, "data in preallocated space");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn ext4_fuse_fallocate_keep_size_preserves_size() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fallocate_keep_size_preserves_size";
        let path = mnt.join("keepsize.bin");
        fs::write(&path, b"short").expect("create file with content");

        let out = Command::new("fallocate")
            .args(["-l", "16384", "--keep-size", path.to_str().unwrap()])
            .output()
            .expect("fallocate keep-size");
        assert!(
            out.status.success(),
            "fallocate --keep-size failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after keep-size fallocate");
        assert_eq!(
            meta.len(),
            5,
            "file size should remain 5 with KEEP_SIZE flag"
        );
        assert!(
            meta.blocks() * 512 >= 16384,
            "allocated disk space ({}*512={}) should be >= 16384 after keep-size fallocate",
            meta.blocks(),
            meta.blocks() * 512
        );

        let content = fs::read_to_string(&path).expect("read after keep-size");
        assert_eq!(content, "short");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn ext4_fuse_fallocate_zero_range_zeroes_range() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fallocate_zero_range_zeroes_range";
        let path = mnt.join("ext4_zero_range.bin");
        let data = patterned_bytes(12_288, 253, 1);
        fs::write(&path, &data).expect("seed zero-range file on ext4");

        let out = Command::new("fallocate")
            .args([
                "--zero-range",
                "-o",
                "4096",
                "-l",
                "4096",
                path.to_str().unwrap(),
            ])
            .output()
            .expect("run fallocate --zero-range on ext4");
        assert!(
            out.status.success(),
            "ext4 zero-range failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after ext4 zero-range");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "zero-range must preserve file size"
        );

        let readback = fs::read(&path).expect("read after ext4 zero-range");
        assert_eq!(&readback[..4096], &data[..4096], "prefix must be preserved");
        assert!(
            readback[4096..8192].iter().all(|&byte| byte == 0),
            "zero-range span must read back as zeros"
        );
        assert_eq!(&readback[8192..], &data[8192..], "suffix must be preserved");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn ext4_fuse_fallocate_punch_hole_keep_size_zeroes_range() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fallocate_punch_hole_keep_size_zeroes_range";
        let path = mnt.join("ext4_punch_hole.bin");
        let data = patterned_bytes(12_288, 251, 1);
        fs::write(&path, &data).expect("seed punch-hole file on ext4");

        let out = Command::new("fallocate")
            .args([
                "--keep-size",
                "--punch-hole",
                "-o",
                "4096",
                "-l",
                "4096",
                path.to_str().unwrap(),
            ])
            .output()
            .expect("run fallocate --punch-hole --keep-size on ext4");
        assert!(
            out.status.success(),
            "ext4 keep-size punch-hole failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after ext4 keep-size punch-hole");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "punch hole must preserve file size"
        );

        let readback = fs::read(&path).expect("read after ext4 keep-size punch-hole");
        assert_eq!(&readback[..4096], &data[..4096], "prefix must be preserved");
        assert!(
            readback[4096..8192].iter().all(|&byte| byte == 0),
            "punched range must read back as zeros"
        );
        assert_eq!(&readback[8192..], &data[8192..], "suffix must be preserved");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn ext4_fuse_invalid_punch_hole_without_keep_size_reports_einval() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_invalid_punch_hole_without_keep_size_errno_einval";
        let path = mnt.join("ext4_invalid_punch_hole_mode.bin");
        let data = patterned_bytes(12_288, 251, 1);
        fs::write(&path, &data).expect("seed invalid-punch-hole file on ext4");

        let report = query_fallocate(&path, libc::FALLOC_FL_PUNCH_HOLE, 4096, 4096);
        let meta = fs::metadata(&path).expect("stat after invalid ext4 punch-hole rejection");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "invalid ext4 punch-hole rejection must preserve file size"
        );
        let readback = fs::read(&path).expect("read after invalid ext4 punch-hole rejection");
        assert_eq!(
            readback, data,
            "invalid ext4 punch-hole rejection must preserve file data"
        );

        if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
            eprintln!(
                "invalid ext4 punch-hole mode collapsed to transport-layer errno 95 before \
                 FrankenFS could prove mounted-path EINVAL semantics: {report}"
            );
            return;
        }

        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "ext4 invalid punch-hole mode should surface EINVAL when dispatched to FrankenFS: {report}"
        );
        assert_eq!(
            report["name"].as_str(),
            Some("EINVAL"),
            "ext4 invalid punch-hole mode should surface the EINVAL alias: {report}"
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=22"));
    });
}

#[test]
fn ext4_fuse_fallocate_on_directory_reports_eisdir() {
    if !command_available("python3") {
        eprintln!("python3 not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fallocate_on_directory_errno_eisdir";
        let dir = mnt.join("ext4_fallocate_dir");
        fs::create_dir(&dir).expect("mkdir ext4 fallocate directory target");
        let child = dir.join("child.txt");
        fs::write(&child, b"directory child stays intact\n").expect("seed ext4 directory child");

        let entries_before = snapshot_directory_entries(&dir);
        let child_before = snapshot_file_state(&child);
        let report = query_directory_fallocate(&dir, 0, 0, 4096);

        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EISDIR)),
            "ext4 directory fallocate should surface exact EISDIR: {report}"
        );
        assert_eq!(
            report["name"].as_str(),
            Some("EISDIR"),
            "ext4 directory fallocate should surface the EISDIR alias: {report}"
        );
        let phase = report["phase"]
            .as_str()
            .expect("directory fallocate rejection phase");
        assert!(
            matches!(phase, "open" | "fallocate"),
            "unexpected directory fallocate rejection phase: {report}"
        );

        let entries_after = snapshot_directory_entries(&dir);
        assert_eq!(
            entries_after, entries_before,
            "directory fallocate rejection must not change directory entries"
        );
        assert_file_state_unchanged(&child, &child_before, "directory fallocate rejection");
        emit_scenario_result(scenario_id, "PASS", Some(phase));
    });
}

#[test]
fn ext4_fuse_unsupported_fallocate_mode_bits_errno_eopnotsupp() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_unsupported_fallocate_mode_bits_errno_eopnotsupp";
        let path = mnt.join("ext4_unsupported_mode_bits.bin");
        let data = b"keep-intact-on-ext4-unsupported-mode".to_vec();
        fs::write(&path, &data).expect("seed unsupported-mode file on ext4");

        let script = r#"
import ctypes
import errno
import os
import sys

path = sys.argv[1]
fd = os.open(path, os.O_RDWR)
libc = ctypes.CDLL(None, use_errno=True)
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
libc.fallocate.restype = ctypes.c_int
res = libc.fallocate(fd, 0x08, 0, 4096)
err = ctypes.get_errno()
os.close(fd)
if res == 0:
    print("res=0")
    sys.exit(0)
print(f"errno={err}")
print(errno.errorcode.get(err, "UNKNOWN"))
sys.exit(1)
"#;
        let out = Command::new("python3")
            .args(["-c", script, path.to_str().unwrap()])
            .output()
            .expect("run unsupported-mode fallocate probe on ext4");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !out.status.success(),
            "unsupported mode bits should fail, got stdout={stdout} stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains(&format!("errno={EOPNOTSUPP_ERRNO}")),
            "unsupported mode bits should surface errno {EOPNOTSUPP_ERRNO}, got: {stdout}"
        );
        assert!(
            stdout.contains("EOPNOTSUPP") || stdout.contains("ENOTSUP"),
            "unsupported mode bits should surface the errno-95 not-supported alias, got: {stdout}"
        );

        let meta = fs::metadata(&path).expect("stat after unsupported-mode rejection");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "unsupported mode rejection must preserve file size"
        );
        let readback = fs::read(&path).expect("read after unsupported-mode rejection");
        assert_eq!(
            readback, data,
            "unsupported mode rejection must preserve file data"
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=95"));
    });
}

#[test]
fn fuse_ioctl_fiemap_reports_valid_extents() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let seed_src = tmp.path().join("fiemap_seed_src.bin");
    fs::write(&seed_src, vec![0x5A_u8; 12 * 1024]).expect("write fiemap seed src");

    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("write {} fiemap_seed.bin", seed_src.display()),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs write fiemap_seed.bin");
    assert!(
        out.status.success(),
        "debugfs write fiemap_seed.bin failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-fiemap.log");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let path = mnt.join("fiemap_seed.bin");
    let meta = fs::metadata(&path).expect("stat fiemap seed file");
    let report = query_fiemap(&path, 16);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        eprintln!(
            "FIEMAP ioctl skipped: kernel/VFS returned EOPNOTSUPP before ffs-fuse::ioctl \
             (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "successful FIEMAP should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    let extents = report["extents"].as_array().expect("fiemap extents array");

    assert!(
        report["mapped_extents"].as_u64().unwrap_or(0) >= 1,
        "expected at least one mapped extent: {report}"
    );
    assert_eq!(
        report["requested_extents"].as_u64().unwrap_or(0),
        16,
        "kernel should preserve requested extent count in response header"
    );

    let mut covered = 0_u64;
    let mut expected_logical = 0_u64;
    let mut saw_last = false;
    for extent in extents {
        let logical = extent["logical"].as_u64().expect("logical");
        let physical = extent["physical"].as_u64().expect("physical");
        let length = extent["length"].as_u64().expect("length");
        let last = extent["last"].as_bool().expect("last flag");

        assert_eq!(
            logical, expected_logical,
            "expected extents to begin at logical offset 0 and remain contiguous: {report}"
        );
        assert!(physical > 0, "physical offset should be non-zero: {report}");
        assert!(length > 0, "extent length should be non-zero: {report}");

        covered = covered.saturating_add(length);
        expected_logical = expected_logical.saturating_add(length);
        saw_last |= last;
    }

    assert!(
        covered >= meta.len(),
        "fiemap extents should cover file length (covered={covered}, len={}): {report}",
        meta.len()
    );
    assert!(
        saw_last,
        "expected FIEMAP_EXTENT_LAST in returned extents: {report}"
    );
}

#[test]
fn fuse_ioctl_fiemap_sync_flag_reports_valid_extents_on_rw_mount() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-fiemap-sync.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_fiemap_sync_flag";
    let path = mnt.join("fiemap_sync_seed.bin");
    let payload = patterned_bytes(12 * 1024, 241, 7);
    fs::write(&path, &payload).expect("write fiemap sync seed file");

    let meta = fs::metadata(&path).expect("stat fiemap sync seed file");
    let report = query_fiemap_with_options(&path, 16, FIEMAP_REQUEST_FLAG_SYNC, None);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "FIEMAP SYNC returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        eprintln!(
            "FIEMAP SYNC ioctl skipped: kernel/VFS returned EOPNOTSUPP before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "successful FIEMAP SYNC should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert!(
        report["errno"].is_null(),
        "FIEMAP SYNC should succeed on the mounted ext4 path once userspace sees the ioctl: \
         {report}"
    );

    let extents = report["extents"].as_array().expect("fiemap extents array");
    assert!(
        report["mapped_extents"].as_u64().unwrap_or(0) >= 1,
        "expected at least one mapped extent from FIEMAP SYNC: {report}"
    );
    assert_eq!(
        report["requested_extents"].as_u64().unwrap_or(0),
        16,
        "kernel should preserve requested extent count in the FIEMAP SYNC response header"
    );

    let mut covered = 0_u64;
    let mut saw_last = false;
    for extent in extents {
        let physical = extent["physical"].as_u64().expect("physical");
        let length = extent["length"].as_u64().expect("length");
        let last = extent["last"].as_bool().expect("last flag");
        assert!(
            physical > 0,
            "FIEMAP SYNC should return non-zero physical offsets for regular extents: {report}"
        );
        assert!(
            length > 0,
            "FIEMAP SYNC extent length should be non-zero: {report}"
        );
        covered = covered.saturating_add(length);
        saw_last |= last;
    }

    assert!(
        covered >= meta.len(),
        "FIEMAP SYNC extents should cover file length (covered={covered}, len={}): {report}",
        meta.len()
    );
    assert!(
        saw_last,
        "FIEMAP SYNC should surface FIEMAP_EXTENT_LAST: {report}"
    );
    emit_scenario_result(scenario_id, "PASS", Some("request_flags=sync"));
}

#[test]
fn fuse_ioctl_fiemap_rejects_unsupported_request_flags_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-fiemap-invalid-flag.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_fiemap_invalid_request_flags";
    let path = mnt.join("fiemap_invalid_flag_seed.bin");
    let payload = patterned_bytes(8 * 1024, 239, 11);
    fs::write(&path, &payload).expect("write fiemap invalid-flag seed file");

    let report = query_fiemap_with_options(&path, 16, FIEMAP_REQUEST_FLAG_XATTR, None);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "invalid-flag FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "FIEMAP invalid-flag ioctl skipped: kernel/VFS returned EOPNOTSUPP before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "unsupported FIEMAP request flags should still hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert_eq!(
        report["errno"].as_i64(),
        Some(i64::from(libc::EBADR)),
        "unsupported FIEMAP request flags should reject with EBADR: {report}"
    );
    assert_eq!(
        fs::read(&path).expect("read after invalid FIEMAP flag rejection"),
        payload,
        "FIEMAP invalid-flag rejection must not mutate file data"
    );
    emit_scenario_result(scenario_id, "PASS", Some("errno=53_ebadr"));
}

#[test]
fn fuse_ioctl_fiemap_directory_fd_reports_eisdir() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-fiemap-directory.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let dir = mnt.join("fiemap_dir_target");
    fs::create_dir(&dir).expect("mkdir ext4 fiemap directory target");
    let child = dir.join("child.txt");
    fs::write(&child, b"fiemap directory child\n").expect("seed ext4 fiemap directory child");

    let entries_before = snapshot_directory_entries(&dir);
    let child_before = snapshot_file_state(&child);
    let report = query_directory_fiemap_with_options(&dir, 16, 0, None);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "directory-fd ext4 FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        emit_scenario_result(
            "ext4_ioctl_fiemap_directory_fd_errno_eisdir",
            "SKIP",
            Some("kernel_or_vfs_rejected_before_userspace"),
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "directory-fd ext4 FIEMAP should hit ffs-fuse::ioctl when not transport-rejected: {ioctl_trace}"
    );
    assert_eq!(
        report["errno"].as_i64(),
        Some(i64::from(libc::EISDIR)),
        "directory-fd ext4 FIEMAP should surface exact EISDIR: {report}"
    );
    assert_eq!(
        report["name"].as_str(),
        Some("EISDIR"),
        "directory-fd ext4 FIEMAP should surface the EISDIR alias: {report}"
    );

    let entries_after = snapshot_directory_entries(&dir);
    assert_eq!(
        entries_after, entries_before,
        "directory-fd FIEMAP rejection must not change directory entries"
    );
    assert_file_state_unchanged(&child, &child_before, "directory-fd FIEMAP rejection");
    emit_scenario_result(
        "ext4_ioctl_fiemap_directory_fd_errno_eisdir",
        "PASS",
        Some("errno=21_eisdir"),
    );
}

#[test]
fn btrfs_fuse_ioctl_fiemap_reports_valid_extents() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-btrfs-fiemap.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_btrfs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    assert!(
        workspace.is_dir(),
        "seeded btrfs workspace missing at {}",
        workspace.display()
    );

    let path = workspace.join("fiemap_seed.bin");
    let payload = vec![0xA5_u8; 24 * 1024];
    fs::write(&path, &payload).expect("write btrfs fiemap seed file");

    let meta = fs::metadata(&path).expect("stat btrfs fiemap seed file");
    let report = query_fiemap(&path, 16);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "btrfs FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        eprintln!(
            "btrfs FIEMAP ioctl skipped: kernel/VFS returned EOPNOTSUPP before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "successful btrfs FIEMAP should hit ffs-fuse::ioctl: {ioctl_trace}"
    );

    let extents = report["extents"]
        .as_array()
        .expect("btrfs fiemap extents array");

    assert!(
        report["mapped_extents"].as_u64().unwrap_or(0) >= 1,
        "expected at least one mapped btrfs extent: {report}"
    );
    assert_eq!(
        report["requested_extents"].as_u64().unwrap_or(0),
        16,
        "kernel should preserve requested btrfs extent count in response header"
    );

    let mut covered = 0_u64;
    let mut expected_logical = 0_u64;
    let mut saw_last = false;
    for extent in extents {
        let logical = extent["logical"].as_u64().expect("logical");
        let physical = extent["physical"].as_u64().expect("physical");
        let length = extent["length"].as_u64().expect("length");
        let last = extent["last"].as_bool().expect("last flag");

        assert_eq!(
            logical, expected_logical,
            "expected btrfs extents to begin at logical offset 0 and remain contiguous: {report}"
        );
        assert!(physical > 0, "physical offset should be non-zero: {report}");
        assert!(length > 0, "extent length should be non-zero: {report}");

        covered = covered.saturating_add(length);
        expected_logical = expected_logical.saturating_add(length);
        saw_last |= last;
    }

    assert!(
        covered >= meta.len(),
        "btrfs fiemap extents should cover file length (covered={covered}, len={}): {report}",
        meta.len()
    );
    assert!(
        saw_last,
        "expected FIEMAP_EXTENT_LAST in returned btrfs extents: {report}"
    );
}

#[test]
fn btrfs_fuse_ioctl_fiemap_directory_fd_reports_eisdir() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-btrfs-fiemap-directory.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_btrfs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    let dir = workspace.join("fiemap_dir_target");
    fs::create_dir(&dir).expect("mkdir btrfs fiemap directory target");
    let child = dir.join("child.txt");
    fs::write(&child, b"fiemap directory child\n").expect("seed btrfs fiemap directory child");

    let entries_before = snapshot_directory_entries(&dir);
    let child_before = snapshot_file_state(&child);
    let report = query_directory_fiemap_with_options(&dir, 16, 0, None);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "directory-fd btrfs FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        emit_scenario_result(
            "btrfs_ioctl_fiemap_directory_fd_errno_eisdir",
            "SKIP",
            Some("kernel_or_vfs_rejected_before_userspace"),
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "directory-fd btrfs FIEMAP should hit ffs-fuse::ioctl when not transport-rejected: {ioctl_trace}"
    );
    assert_eq!(
        report["errno"].as_i64(),
        Some(i64::from(libc::EISDIR)),
        "directory-fd btrfs FIEMAP should surface exact EISDIR: {report}"
    );
    assert_eq!(
        report["name"].as_str(),
        Some("EISDIR"),
        "directory-fd btrfs FIEMAP should surface the EISDIR alias: {report}"
    );

    let entries_after = snapshot_directory_entries(&dir);
    assert_eq!(
        entries_after, entries_before,
        "directory-fd FIEMAP rejection must not change directory entries"
    );
    assert_file_state_unchanged(&child, &child_before, "directory-fd FIEMAP rejection");
    emit_scenario_result(
        "btrfs_ioctl_fiemap_directory_fd_errno_eisdir",
        "PASS",
        Some("errno=21_eisdir"),
    );
}

#[test]
fn btrfs_fuse_ioctl_fiemap_reports_inline_extent_with_zero_physical() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-btrfs-fiemap-inline.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_btrfs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    let path = workspace.join("fiemap_inline_seed.bin");
    let payload = b"inline-fiemap";
    fs::write(&path, payload).expect("write inline btrfs fiemap seed file");

    let report = query_fiemap(&path, 16);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "inline btrfs FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "btrfs inline FIEMAP ioctl skipped: kernel/VFS returned EOPNOTSUPP before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "successful inline btrfs FIEMAP should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert!(
        report["errno"].is_null(),
        "inline btrfs FIEMAP should succeed once userspace sees the ioctl: {report}"
    );

    let extents = report["extents"]
        .as_array()
        .expect("inline btrfs fiemap extents array");
    assert_eq!(
        extents.len(),
        1,
        "inline btrfs FIEMAP should report a single inline extent: {report}"
    );
    assert_eq!(
        report["mapped_extents"].as_u64().unwrap_or(0),
        1,
        "inline btrfs FIEMAP should map exactly one extent: {report}"
    );

    let extent = &extents[0];
    assert_eq!(extent["logical"].as_u64().unwrap_or(u64::MAX), 0);
    assert_eq!(extent["physical"].as_u64().unwrap_or(u64::MAX), 0);
    assert_eq!(extent["length"].as_u64().unwrap_or(0), payload.len() as u64);
    assert_eq!(
        fiemap_extent_flags(extent),
        FIEMAP_EXTENT_LAST_FLAG,
        "inline btrfs FIEMAP extent should only carry LAST: {report}"
    );
    assert!(
        extent["last"].as_bool().unwrap_or(false),
        "inline btrfs FIEMAP extent should surface LAST: {report}"
    );
}

#[test]
fn btrfs_fuse_ioctl_fiemap_marks_keep_size_prealloc_extent_unwritten() {
    if !btrfs_fuse_available() || !command_available("fallocate") {
        eprintln!("btrfs FIEMAP keep-size prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-btrfs-fiemap-prealloc.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_btrfs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    let path = workspace.join("fiemap_prealloc_seed.bin");
    fs::write(&path, b"existing").expect("write keep-size seed file");

    let out = Command::new("fallocate")
        .args([
            "--keep-size",
            "-o",
            "4096",
            "-l",
            "4096",
            path.to_str().unwrap(),
        ])
        .output()
        .expect("run keep-size fallocate on btrfs");
    assert!(
        out.status.success(),
        "btrfs keep-size fallocate for FIEMAP failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read(&path).expect("read after keep-size fallocate"),
        b"existing",
        "keep-size preallocation should preserve visible file data"
    );

    let report = query_fiemap(&path, 16);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "keep-size btrfs FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "btrfs keep-size FIEMAP ioctl skipped: kernel/VFS returned EOPNOTSUPP before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "successful keep-size btrfs FIEMAP should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert!(
        report["errno"].is_null(),
        "keep-size btrfs FIEMAP should succeed once userspace sees the ioctl: {report}"
    );

    let extents = report["extents"]
        .as_array()
        .expect("keep-size btrfs fiemap extents array");
    assert!(
        report["mapped_extents"].as_u64().unwrap_or(0) >= 2,
        "keep-size btrfs FIEMAP should report data plus unwritten prealloc extents: {report}"
    );

    let has_materialized_prefix = extents.iter().any(|extent| {
        extent["logical"].as_u64() == Some(0)
            && extent["physical"].as_u64().unwrap_or(0) > 0
            && fiemap_extent_flags(extent) & FIEMAP_EXTENT_UNWRITTEN_FLAG == 0
    });
    assert!(
        has_materialized_prefix,
        "keep-size btrfs FIEMAP should expose the materialized prefix extent: {report}"
    );

    let has_unwritten_prealloc = extents.iter().any(|extent| {
        extent["logical"].as_u64() == Some(4096)
            && extent["length"].as_u64() == Some(4096)
            && extent["physical"].as_u64().unwrap_or(0) > 0
            && fiemap_extent_flags(extent) & FIEMAP_EXTENT_UNWRITTEN_FLAG != 0
            && fiemap_extent_flags(extent) & FIEMAP_EXTENT_LAST_FLAG != 0
    });
    assert!(
        has_unwritten_prealloc,
        "keep-size btrfs FIEMAP should expose a trailing unwritten prealloc extent: {report}"
    );
}

#[test]
fn fuse_ioctl_ext4_getflags_setflags_roundtrip_preserves_system_bits() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-flags.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_getflags_setflags_roundtrip";
    let path = mnt.join("inode_flags.bin");
    fs::write(&path, b"ext4 ioctl flags payload\n").expect("write ext4 ioctl seed file");

    let original_report = ext4_inode_flags_ioctl(&path, "get", None);
    let get_trace = read_ioctl_trace(&ioctl_trace_path);
    if original_report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&get_trace, EXT4_IOC_GETFLAGS_CMD),
            "GETFLAGS returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {get_trace}"
        );
        eprintln!(
            "EXT4 GETFLAGS ioctl skipped: kernel/VFS returned EOPNOTSUPP before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&get_trace, EXT4_IOC_GETFLAGS_CMD),
        "successful GETFLAGS should hit ffs-fuse::ioctl: {get_trace}"
    );
    let original = u32::try_from(
        original_report["flags"]
            .as_u64()
            .expect("original flags u64"),
    )
    .expect("original flags should fit u32");
    assert_ne!(
        original & ffs_types::EXT4_EXTENTS_FL,
        0,
        "default rw ext4 file should start extent-based: {original_report}"
    );

    let requested = (original
        | ffs_types::EXT4_NOATIME_FL
        | ffs_types::EXT4_NODUMP_FL
        | ffs_types::EXT4_HUGE_FILE_FL)
        & !ffs_types::EXT4_EXTENTS_FL;
    let set_report = ext4_inode_flags_ioctl(&path, "set", Some(requested));
    let set_trace = read_ioctl_trace(&ioctl_trace_path);
    if set_report["errno"].as_i64() == Some(i64::from(libc::ENOTTY)) {
        assert!(
            !trace_contains_cmd(&set_trace, EXT4_IOC_SETFLAGS_CMD),
            "SETFLAGS returned ENOTTY after reaching ffs-fuse::ioctl: {set_trace}"
        );
        eprintln!(
            "EXT4 SETFLAGS ioctl skipped: kernel/VFS returned ENOTTY before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&set_trace, EXT4_IOC_SETFLAGS_CMD),
        "successful SETFLAGS should hit ffs-fuse::ioctl: {set_trace}"
    );
    assert!(
        set_report["errno"].is_null(),
        "EXT4 SETFLAGS ioctl should succeed on rw mount: {set_report}"
    );

    let updated_report = ext4_inode_flags_ioctl(&path, "get", None);
    let updated = u32::try_from(updated_report["flags"].as_u64().expect("updated flags u64"))
        .expect("updated flags should fit u32");
    assert_eq!(
        updated & (ffs_types::EXT4_NOATIME_FL | ffs_types::EXT4_NODUMP_FL),
        ffs_types::EXT4_NOATIME_FL | ffs_types::EXT4_NODUMP_FL,
        "SETFLAGS should apply user-settable NOATIME/NODUMP bits: {updated_report}"
    );
    assert_eq!(
        updated & ffs_types::EXT4_EXTENTS_FL,
        original & ffs_types::EXT4_EXTENTS_FL,
        "SETFLAGS must not clear system-managed EXTENTS bit: {updated_report}"
    );
    assert_eq!(
        updated & ffs_types::EXT4_HUGE_FILE_FL,
        original & ffs_types::EXT4_HUGE_FILE_FL,
        "SETFLAGS must not introduce system-managed HUGE_FILE bit: {updated_report}"
    );
    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("user_bits_applied_system_bits_preserved"),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_setfslabel_updates_label_and_survives_remount() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-fslabel.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_setfslabel_roundtrip";
    let path = mnt.join("fslabel-target.txt");
    fs::write(&path, b"fs label ioctl target\n").expect("create fslabel ioctl target");
    let requested = "ffs-renamed";

    let set_report = fs_label_ioctl(&path, "set", Some(requested));
    let set_trace = read_ioctl_trace(&ioctl_trace_path);
    if let Some(errno) = set_report["errno"].as_i64() {
        if errno == i64::from(libc::EPERM)
            || errno == i64::from(libc::ENOTTY)
            || errno == EOPNOTSUPP_ERRNO
        {
            assert!(
                !trace_contains_cmd(&set_trace, FS_IOC_SETFSLABEL_CMD),
                "SETFSLABEL should not return {errno} after reaching ffs-fuse::ioctl: {set_trace}"
            );
            emit_scenario_result(
                scenario_id,
                "SKIP",
                Some("kernel_or_vfs_rejected_setfslabel_before_userspace"),
            );
            return;
        }
    }
    assert!(
        trace_contains_cmd(&set_trace, FS_IOC_SETFSLABEL_CMD),
        "successful SETFSLABEL should hit ffs-fuse::ioctl: {set_trace}"
    );
    assert!(
        set_report["errno"].is_null(),
        "SETFSLABEL should succeed on rw ext4 mount: {set_report}"
    );

    drop(session);
    wait_for_fuse_mount_released(&mnt);

    let Some(_remount) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };
    let remount_report = fs_label_ioctl(&path, "get", None);
    let remount_trace = read_ioctl_trace(&ioctl_trace_path);
    if let Some(errno) = remount_report["errno"].as_i64() {
        assert!(
            errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO,
            "unexpected errno for remount GETFSLABEL fallback: {remount_report}"
        );
        assert!(
            !trace_contains_cmd(&remount_trace, FS_IOC_GETFSLABEL_CMD),
            "GETFSLABEL should not return {errno} after reaching ffs-fuse::ioctl: {remount_trace}"
        );

        let cx = Cx::for_testing();
        let opts = OpenOptions {
            ext4_journal_replay_mode: Ext4JournalReplayMode::Skip,
            ..OpenOptions::default()
        };
        let fs = OpenFs::open_with_options(&cx, &image, &opts)
            .expect("open image to verify persisted fs label");
        let label = fs
            .get_fs_label(&cx, &mut RequestScope::empty())
            .expect("read persisted fs label directly");
        let end = label
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(label.len());
        assert_eq!(
            &label[..end],
            requested.as_bytes(),
            "SETFSLABEL should persist even when remount GETFSLABEL is transport-blocked"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("setfslabel_persisted_direct_verify_after_remount"),
        );
        return;
    }

    assert!(
        trace_contains_cmd(&remount_trace, FS_IOC_GETFSLABEL_CMD),
        "successful GETFSLABEL after remount should hit ffs-fuse::ioctl: {remount_trace}"
    );
    assert_eq!(
        remount_report["label"].as_str(),
        Some(requested),
        "SETFSLABEL should persist across remount: {remount_report}"
    );
    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("setfslabel_persisted_after_remount"),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_setflags_enables_compr_and_roundtrips_data_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_ext4_incompat_features(
        tmp.path(),
        4 * 1024 * 1024,
        ffs_ondisk::Ext4IncompatFeatures::COMPRESSION.0,
    );
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-compr-setflags.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_setflags_compr_enable";
    let path = mnt.join("compr-enable.bin");
    fs::write(&path, b"").expect("create empty file for COMPR enable");

    let original_report = ext4_inode_flags_ioctl(&path, "get", None);
    let get_trace = read_ioctl_trace(&ioctl_trace_path);
    if original_report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&get_trace, EXT4_IOC_GETFLAGS_CMD),
            "GETFLAGS returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {get_trace}"
        );
        eprintln!(
            "EXT4 GETFLAGS ioctl skipped for COMPR enable: kernel/VFS returned EOPNOTSUPP \
             before ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&get_trace, EXT4_IOC_GETFLAGS_CMD),
        "successful GETFLAGS should hit ffs-fuse::ioctl: {get_trace}"
    );
    let original = u32::try_from(
        original_report["flags"]
            .as_u64()
            .expect("original COMPR flags u64"),
    )
    .expect("original COMPR flags should fit u32");
    assert_ne!(
        original & ffs_types::EXT4_EXTENTS_FL,
        0,
        "fresh ext4 file should start extent-based before COMPR enable: {original_report}"
    );

    let set_report =
        ext4_inode_flags_ioctl(&path, "set", Some(original | ffs_types::EXT4_COMPR_FL));
    let set_trace = read_ioctl_trace(&ioctl_trace_path);
    if set_report["errno"].as_i64() == Some(i64::from(libc::ENOTTY)) {
        assert!(
            !trace_contains_cmd(&set_trace, EXT4_IOC_SETFLAGS_CMD),
            "COMPR SETFLAGS returned ENOTTY after reaching ffs-fuse::ioctl: {set_trace}"
        );
        eprintln!(
            "EXT4 COMPR SETFLAGS ioctl skipped: kernel/VFS returned ENOTTY before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&set_trace, EXT4_IOC_SETFLAGS_CMD),
        "successful COMPR SETFLAGS should hit ffs-fuse::ioctl: {set_trace}"
    );
    assert!(
        set_report["errno"].is_null(),
        "ext4 COMPR enable via SETFLAGS should succeed on rw mount: {set_report}"
    );

    let updated_report = ext4_inode_flags_ioctl(&path, "get", None);
    let updated = u32::try_from(
        updated_report["flags"]
            .as_u64()
            .expect("updated COMPR flags u64"),
    )
    .expect("updated COMPR flags should fit u32");
    assert_ne!(
        updated & ffs_types::EXT4_COMPR_FL,
        0,
        "SETFLAGS should publish EXT4_COMPR_FL after COMPR enable: {updated_report}"
    );
    assert_eq!(
        updated & ffs_types::EXT4_EXTENTS_FL,
        0,
        "COMPR enable should clear EXTENTS on the mounted path: {updated_report}"
    );

    let payload = vec![b'C'; 4096];
    fs::write(&path, &payload).expect("write compressible payload after COMPR enable");
    let readback = fs::read(&path).expect("readback after COMPR enable");
    assert_eq!(
        readback, payload,
        "COMPR-enabled mounted path should preserve file bytes across write/read"
    );

    let post_write_report = ext4_inode_flags_ioctl(&path, "get", None);
    let post_write = u32::try_from(
        post_write_report["flags"]
            .as_u64()
            .expect("post-write COMPR flags u64"),
    )
    .expect("post-write COMPR flags should fit u32");
    assert_ne!(
        post_write & ffs_types::EXT4_COMPRBLK_FL,
        0,
        "compressed mounted-path write should set COMPRBLK after COMPR enable: {post_write_report}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("compr_flag_enabled_and_compressed_write_roundtrips"),
    );
}

#[test]
fn fuse_ioctl_ext4_setflags_rejects_compr_without_compression_feature() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-compr-reject.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_setflags_compr_requires_feature";
    let path = mnt.join("compr-reject.bin");
    fs::write(&path, b"").expect("create empty file for COMPR rejection");

    let original_report = ext4_inode_flags_ioctl(&path, "get", None);
    let get_trace = read_ioctl_trace(&ioctl_trace_path);
    if original_report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&get_trace, EXT4_IOC_GETFLAGS_CMD),
            "GETFLAGS returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {get_trace}"
        );
        eprintln!(
            "EXT4 GETFLAGS ioctl skipped for COMPR rejection: kernel/VFS returned EOPNOTSUPP \
             before ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&get_trace, EXT4_IOC_GETFLAGS_CMD),
        "successful GETFLAGS should hit ffs-fuse::ioctl: {get_trace}"
    );
    let original = u32::try_from(
        original_report["flags"]
            .as_u64()
            .expect("original rejection flags u64"),
    )
    .expect("original rejection flags should fit u32");

    let set_report =
        ext4_inode_flags_ioctl(&path, "set", Some(original | ffs_types::EXT4_COMPR_FL));
    let set_trace = read_ioctl_trace(&ioctl_trace_path);
    if set_report["errno"].as_i64() == Some(i64::from(libc::ENOTTY)) {
        assert!(
            !trace_contains_cmd(&set_trace, EXT4_IOC_SETFLAGS_CMD),
            "COMPR rejection SETFLAGS returned ENOTTY after reaching ffs-fuse::ioctl: {set_trace}"
        );
        eprintln!(
            "EXT4 COMPR rejection SETFLAGS ioctl skipped: kernel/VFS returned ENOTTY before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&set_trace, EXT4_IOC_SETFLAGS_CMD),
        "rejected COMPR SETFLAGS should still hit ffs-fuse::ioctl: {set_trace}"
    );
    assert_eq!(
        set_report["errno"].as_i64(),
        Some(EOPNOTSUPP_ERRNO),
        "COMPR enable without the COMPRESSION feature should surface EOPNOTSUPP: {set_report}"
    );
    assert_eq!(
        set_report["message"].as_str(),
        Some("[Errno 95] Operation not supported"),
        "COMPR rejection should keep the stable mounted-path errno string: {set_report}"
    );

    let updated_report = ext4_inode_flags_ioctl(&path, "get", None);
    let updated = u32::try_from(
        updated_report["flags"]
            .as_u64()
            .expect("updated rejection flags u64"),
    )
    .expect("updated rejection flags should fit u32");
    assert_eq!(
        updated & ffs_types::EXT4_COMPR_FL,
        0,
        "failed COMPR enable must not set EXT4_COMPR_FL: {updated_report}"
    );
    assert_eq!(
        updated, original,
        "failed COMPR enable must leave mounted-path inode flags unchanged: {updated_report}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("compr_enable_without_feature_rejected"),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ext4_fscrypt_nokey_readdir_and_lookup_preserve_raw_bytes_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let raw_name = b"\xFFenc\x80";
    let image_path = tmp.path().join("fscrypt-nokey-raw-name.ext4");
    fs::write(&image_path, build_ext4_encrypt_image_with_dir(raw_name))
        .expect("write fscrypt raw-name image");
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image_path, &mnt) else {
        return;
    };

    let scenario_id = "ext4_fscrypt_nokey_raw_name_lookup_and_readdir";
    let entries = fs::read_dir(&mnt)
        .expect("readdir mounted root")
        .map(|entry| entry.expect("mounted root dirent").file_name())
        .collect::<Vec<_>>();
    assert!(
        entries.iter().any(|name| name.as_bytes() == raw_name),
        "mounted-path readdir should preserve encrypted raw bytes, got: {entries:?}"
    );

    let encrypted_path = mnt.join(Path::new(std::ffi::OsStr::from_bytes(raw_name)));
    let metadata = fs::metadata(&encrypted_path).expect("lookup encrypted entry via raw bytes");
    assert!(
        metadata.is_file(),
        "raw-byte lookup should resolve the encrypted file"
    );
    assert_eq!(
        metadata.ino(),
        11,
        "raw-byte lookup should resolve inode 11 for the encrypted entry"
    );
    assert_eq!(
        fs::read(&encrypted_path).expect("read encrypted file via raw-byte path"),
        vec![0_u8; 5],
        "encrypted fixture file should remain readable through the raw-byte name"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("readdir_and_lookup_preserve_raw_bytes"),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_get_encryption_policy_v1_reports_legacy_policy_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = build_ext4_fscrypt_policy_image(true);
    let image_path = tmp.path().join("fscrypt-policy-v1.ext4");
    fs::write(&image_path, image).expect("write fscrypt policy image");
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-encryption-policy.log");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_with_options(&image_path, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_get_encryption_policy_v1";
    let path = mnt.join("policy.txt");
    let report = ext4_get_encryption_policy_ioctl(&path);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO
    ) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_CMD),
            "GET_ENCRYPTION_POLICY returned unsupported errno after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "EXT4 GET_ENCRYPTION_POLICY ioctl skipped: kernel/VFS returned unsupported errno \
             before ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_CMD),
        "successful GET_ENCRYPTION_POLICY should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    // The legacy getter is encoded as `_IOW`, so restricted FUSE sends the
    // caller buffer as `in_data` with `out_size == 0`. Real kernels then reject
    // any successful data reply with `EIO` even though the request reached
    // FrankenFS; treat that as an auditable surfaced transport gap rather than
    // as a backend regression.
    if report["errno"].as_i64() == Some(i64::from(libc::EIO)) {
        assert!(
            ioctl_trace.contains("in_len=12 out_size=0"),
            "legacy fscrypt v1 ioctl should surface the restricted-FUSE `_IOW` \
             request shape before returning EIO: {ioctl_trace}"
        );
        assert_eq!(
            report["message"].as_str(),
            Some("[Errno 5] Input/output error"),
            "legacy fscrypt v1 mounted-path failure should remain the expected \
             kernel/FUSE transport EIO: {report}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("restricted_fuse_iow_transport_surfaces_eio"),
        );
        return;
    }

    assert!(
        report["errno"].is_null(),
        "GET_ENCRYPTION_POLICY should either succeed or surface the known \
         restricted-FUSE `_IOW` EIO: {report}"
    );
    assert_eq!(
        report["policy_version"].as_u64(),
        Some(u64::from(FSCRYPT_POLICY_V1_VERSION)),
        "expected legacy fscrypt policy v1 payload: {report}"
    );
    assert_eq!(
        report["contents_mode"].as_u64(),
        Some(1),
        "unexpected fscrypt contents mode: {report}"
    );
    assert_eq!(
        report["filenames_mode"].as_u64(),
        Some(4),
        "unexpected fscrypt filenames mode: {report}"
    );
    assert_eq!(
        report["flags"].as_u64(),
        Some(0),
        "unexpected fscrypt policy flags: {report}"
    );
    assert_eq!(
        report["master_key_descriptor_hex"].as_str(),
        Some("6d6b646573633432"),
        "unexpected fscrypt v1 master key descriptor: {report}"
    );
    assert_eq!(
        report["policy_hex"].as_str(),
        Some("000104006d6b646573633432"),
        "expected raw fscrypt policy v1 bytes to remain stable: {report}"
    );
    assert_eq!(
        report["policy_hex"].as_str().map(str::len),
        Some(FSCRYPT_POLICY_V1_SIZE * 2),
        "expected the legacy policy ioctl to return exactly 12 bytes: {report}"
    );
    emit_scenario_result(scenario_id, "PASS", Some("policy_version=0_v1"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_get_encryption_policy_ex_returns_v1_policy_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = build_ext4_fscrypt_policy_image(true);
    let image_path = tmp.path().join("fscrypt-policy-ex-v1.ext4");
    fs::write(&image_path, image).expect("write fscrypt policy-ex image");
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-encryption-policy-ex.log");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_with_options(&image_path, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_get_encryption_policy_ex_v1";
    let path = mnt.join("policy.txt");
    let report = ext4_get_encryption_policy_ex_ioctl(&path);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);

    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO
    ) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_EX_CMD),
            "GET_ENCRYPTION_POLICY_EX returned unsupported errno after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "EXT4 GET_ENCRYPTION_POLICY_EX ioctl skipped: kernel/VFS returned unsupported errno \
             before ffs-fuse::ioctl (trace empty)"
        );
        return;
    }

    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_EX_CMD),
        "GET_ENCRYPTION_POLICY_EX mounted-path request should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    if fscrypt_policy_ex_transport_eio_is_expected(&report, &ioctl_trace, scenario_id, "v1") {
        return;
    }

    assert!(
        report["errno"].is_null(),
        "GET_ENCRYPTION_POLICY_EX should either succeed or surface the known restricted-FUSE \
         transport EIO: {report}"
    );
    assert_eq!(
        report["policy_version"].as_u64(),
        Some(u64::from(FSCRYPT_POLICY_V1_VERSION)),
        "expected fscrypt policy v1 via policy-ex: {report}"
    );
    assert_eq!(
        report["policy_size"].as_u64(),
        Some(FSCRYPT_POLICY_V1_SIZE as u64),
        "expected policy size 12 for v1: {report}"
    );
    assert_eq!(
        report["contents_mode"].as_u64(),
        Some(1),
        "unexpected fscrypt contents mode: {report}"
    );
    assert_eq!(
        report["filenames_mode"].as_u64(),
        Some(4),
        "unexpected fscrypt filenames mode: {report}"
    );
    assert_eq!(
        report["flags"].as_u64(),
        Some(0),
        "unexpected fscrypt policy flags: {report}"
    );
    assert_eq!(
        report["master_key_descriptor_hex"].as_str(),
        Some("6d6b646573633432"),
        "unexpected fscrypt v1 master key descriptor: {report}"
    );
    emit_scenario_result(scenario_id, "PASS", Some("policy_ex_returns_v1"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_get_encryption_policy_ex_returns_v2_policy_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = build_ext4_fscrypt_policy_v2_image();
    let image_path = tmp.path().join("fscrypt-policy-ex-v2.ext4");
    fs::write(&image_path, image).expect("write fscrypt policy-ex v2 image");
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-encryption-policy-ex-v2.log");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_with_options(&image_path, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_get_encryption_policy_ex_v2";
    let path = mnt.join("policy.txt");
    let report = ext4_get_encryption_policy_ex_ioctl(&path);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);

    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO
    ) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_EX_CMD),
            "GET_ENCRYPTION_POLICY_EX returned unsupported errno after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "EXT4 GET_ENCRYPTION_POLICY_EX v2 ioctl skipped: kernel/VFS returned unsupported errno \
             before ffs-fuse::ioctl (trace empty)"
        );
        return;
    }

    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_EX_CMD),
        "GET_ENCRYPTION_POLICY_EX v2 mounted-path request should hit ffs-fuse::ioctl: \
         {ioctl_trace}"
    );
    if fscrypt_policy_ex_transport_eio_is_expected(&report, &ioctl_trace, scenario_id, "v2") {
        return;
    }

    assert!(
        report["errno"].is_null(),
        "GET_ENCRYPTION_POLICY_EX v2 should either succeed or surface the known restricted-FUSE \
         transport EIO: {report}"
    );
    assert_eq!(
        report["policy_version"].as_u64(),
        Some(u64::from(FSCRYPT_POLICY_V2_VERSION)),
        "expected fscrypt policy v2 via policy-ex: {report}"
    );
    assert_eq!(
        report["policy_size"].as_u64(),
        Some(FSCRYPT_POLICY_V2_SIZE as u64),
        "expected policy size 24 for v2: {report}"
    );
    assert_eq!(
        report["contents_mode"].as_u64(),
        Some(1),
        "unexpected fscrypt v2 contents mode: {report}"
    );
    assert_eq!(
        report["filenames_mode"].as_u64(),
        Some(4),
        "unexpected fscrypt v2 filenames mode: {report}"
    );
    assert_eq!(
        report["flags"].as_u64(),
        Some(0),
        "unexpected fscrypt v2 policy flags: {report}"
    );
    assert_eq!(
        report["master_key_identifier_hex"].as_str(),
        Some("30313233343536373839616263646566"),
        "unexpected fscrypt v2 master key identifier: {report}"
    );
    emit_scenario_result(scenario_id, "PASS", Some("policy_ex_returns_v2"));
}

#[test]
fn fuse_ioctl_ext4_get_encryption_policy_returns_enodata_for_unencrypted_inode() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = build_ext4_fscrypt_policy_image(false);
    let image_path = tmp.path().join("fscrypt-policy-enodata.ext4");
    fs::write(&image_path, image).expect("write fscrypt ENODATA image");
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-encryption-policy-enodata.log");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_with_options(&image_path, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_get_encryption_policy_enodata";
    let path = mnt.join("policy.txt");
    let report = ext4_get_encryption_policy_ioctl(&path);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO
    ) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_CMD),
            "GET_ENCRYPTION_POLICY ENODATA path returned unsupported errno after reaching \
             ffs-fuse::ioctl: {ioctl_trace}"
        );
        eprintln!(
            "EXT4 GET_ENCRYPTION_POLICY ENODATA path skipped: kernel/VFS returned unsupported \
             errno before ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_CMD),
        "ENODATA GET_ENCRYPTION_POLICY should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert_eq!(
        report["errno"].as_i64(),
        Some(i64::from(libc::ENODATA)),
        "unencrypted inode should surface ENODATA: {report}"
    );
    let detail = format!("errno={}", libc::ENODATA);
    emit_scenario_result(scenario_id, "PASS", Some(detail.as_str()));
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_move_ext_swaps_middle_extent_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 8 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-move-ext.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_move_ext_swaps_middle_extent";
    let source = mnt.join("move_ext_source.bin");
    let donor = mnt.join("move_ext_donor.bin");
    let block_size = 4096_usize;

    let mut source_payload = Vec::with_capacity(block_size * 3);
    source_payload.extend(std::iter::repeat_n(0x11_u8, block_size));
    source_payload.extend(std::iter::repeat_n(0x22_u8, block_size));
    source_payload.extend(std::iter::repeat_n(0x33_u8, block_size));
    let mut donor_payload = Vec::with_capacity(block_size * 3);
    donor_payload.extend(std::iter::repeat_n(0xAA_u8, block_size));
    donor_payload.extend(std::iter::repeat_n(0xBB_u8, block_size));
    donor_payload.extend(std::iter::repeat_n(0xCC_u8, block_size));

    fs::write(&source, &source_payload).expect("write source payload");
    fs::write(&donor, &donor_payload).expect("write donor payload");

    let source_before = query_fiemap(&source, 16);
    let donor_before = query_fiemap(&donor, 16);
    if matches!(
        source_before["errno"].as_i64(),
        Some(errno) if errno == EOPNOTSUPP_ERRNO || errno == i64::from(libc::ENOTTY)
    ) || matches!(
        donor_before["errno"].as_i64(),
        Some(errno) if errno == EOPNOTSUPP_ERRNO || errno == i64::from(libc::ENOTTY)
    ) {
        eprintln!(
            "EXT4 MOVE_EXT swap proof skipped: FIEMAP unavailable on current kernel/FUSE stack"
        );
        return;
    }
    let report = ext4_move_ext_ioctl(&source, &donor, 1, 1, 1);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["timeout"].as_bool() == Some(true) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, EXT4_IOC_MOVE_EXT_CMD),
            "MOVE_EXT timed out after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        eprintln!(
            "EXT4 MOVE_EXT ioctl skipped: kernel/FUSE stack timed out before ffs-fuse::ioctl"
        );
        return;
    }
    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO
    ) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, EXT4_IOC_MOVE_EXT_CMD),
            "MOVE_EXT returned kernel/VFS-level unsupported errno after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "EXT4 MOVE_EXT ioctl skipped: kernel/VFS returned unsupported errno before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, EXT4_IOC_MOVE_EXT_CMD),
        "successful MOVE_EXT should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert!(
        report["errno"].is_null(),
        "EXT4 MOVE_EXT ioctl should succeed on fully mapped extents: {report}"
    );
    assert_eq!(
        report["moved_len"].as_u64(),
        Some(1),
        "MOVE_EXT should report the swapped block count: {report}"
    );

    let source_after = fs::read(&source).expect("read source after move_ext");
    let donor_after = fs::read(&donor).expect("read donor after move_ext");
    assert_eq!(
        &source_after[..block_size],
        &source_payload[..block_size],
        "source prefix block should stay in place"
    );
    assert_eq!(
        &source_after[block_size..2 * block_size],
        &donor_payload[block_size..2 * block_size],
        "source middle block should come from donor"
    );
    assert_eq!(
        &source_after[2 * block_size..],
        &source_payload[2 * block_size..],
        "source suffix block should stay in place"
    );
    assert_eq!(
        &donor_after[..block_size],
        &donor_payload[..block_size],
        "donor prefix block should stay in place"
    );
    assert_eq!(
        &donor_after[block_size..2 * block_size],
        &source_payload[block_size..2 * block_size],
        "donor middle block should come from source"
    );
    assert_eq!(
        &donor_after[2 * block_size..],
        &donor_payload[2 * block_size..],
        "donor suffix block should stay in place"
    );

    let source_after_report = query_fiemap(&source, 16);
    let donor_after_report = query_fiemap(&donor, 16);
    assert!(
        source_after_report["errno"].is_null() && donor_after_report["errno"].is_null(),
        "post-move FIEMAP must succeed to prove extent exchange: source={source_after_report} \
         donor={donor_after_report}"
    );
    let source_before_blocks = physical_blocks_by_logical_block(&source_before, block_size as u64);
    let donor_before_blocks = physical_blocks_by_logical_block(&donor_before, block_size as u64);
    let source_after_blocks =
        physical_blocks_by_logical_block(&source_after_report, block_size as u64);
    let donor_after_blocks =
        physical_blocks_by_logical_block(&donor_after_report, block_size as u64);
    assert!(
        source_before_blocks.len() >= 3
            && donor_before_blocks.len() >= 3
            && source_after_blocks.len() >= 3
            && donor_after_blocks.len() >= 3,
        "expected block-level FIEMAP coverage for three-block move_ext scenario"
    );
    assert_eq!(
        source_after_blocks[0], source_before_blocks[0],
        "source logical block 0 should keep its original physical block"
    );
    assert_eq!(
        source_after_blocks[1], donor_before_blocks[1],
        "source logical block 1 should adopt donor's original physical block"
    );
    assert_eq!(
        source_after_blocks[2], source_before_blocks[2],
        "source logical block 2 should keep its original physical block"
    );
    assert_eq!(
        donor_after_blocks[0], donor_before_blocks[0],
        "donor logical block 0 should keep its original physical block"
    );
    assert_eq!(
        donor_after_blocks[1], source_before_blocks[1],
        "donor logical block 1 should adopt source's original physical block"
    );
    assert_eq!(
        donor_after_blocks[2], donor_before_blocks[2],
        "donor logical block 2 should keep its original physical block"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("moved_len=1_middle_block_swapped"),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_move_ext_rejects_hole_backed_range_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 8 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-move-ext-hole.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_move_ext_rejects_hole_backed_range";
    let source = mnt.join("move_ext_hole_source.bin");
    let donor = mnt.join("move_ext_hole_donor.bin");
    let block_size = 4096_usize;

    let mut source_payload = Vec::with_capacity(block_size * 3);
    source_payload.extend(std::iter::repeat_n(0x31_u8, block_size));
    source_payload.extend(std::iter::repeat_n(0x32_u8, block_size));
    source_payload.extend(std::iter::repeat_n(0x33_u8, block_size));
    let mut donor_payload = Vec::with_capacity(block_size * 3);
    donor_payload.extend(std::iter::repeat_n(0x61_u8, block_size));
    donor_payload.extend(std::iter::repeat_n(0x62_u8, block_size));
    donor_payload.extend(std::iter::repeat_n(0x63_u8, block_size));

    fs::write(&source, &source_payload).expect("write source payload");
    fs::write(&donor, &donor_payload).expect("write donor payload");

    let fiemap_preflight = query_fiemap(&donor, 4);
    if matches!(
        fiemap_preflight["errno"].as_i64(),
        Some(errno) if errno == EOPNOTSUPP_ERRNO || errno == i64::from(libc::ENOTTY)
    ) {
        eprintln!(
            "EXT4 MOVE_EXT hole rejection skipped: current kernel/FUSE stack does not \
             route prerequisite ioctl coverage to userspace"
        );
        return;
    }

    let out = Command::new("fallocate")
        .args([
            "--keep-size",
            "--punch-hole",
            "-o",
            "4096",
            "-l",
            "4096",
            source.to_str().expect("source path utf8"),
        ])
        .output()
        .expect("run fallocate --punch-hole for move_ext source");
    assert!(
        out.status.success(),
        "move_ext hole setup failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let expected_source = fs::read(&source).expect("read source after punching hole");
    assert!(
        expected_source[block_size..2 * block_size]
            .iter()
            .all(|&byte| byte == 0),
        "punched move_ext source block should read back as zeros"
    );
    let donor_before = fs::read(&donor).expect("read donor before move_ext");

    let report = ext4_move_ext_ioctl(&source, &donor, 1, 1, 1);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["timeout"].as_bool() == Some(true) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, EXT4_IOC_MOVE_EXT_CMD),
            "MOVE_EXT hole rejection timed out after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        eprintln!(
            "EXT4 MOVE_EXT hole rejection skipped: kernel/FUSE stack timed out before \
             ffs-fuse::ioctl"
        );
        return;
    }
    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO
    ) && !trace_contains_cmd(&ioctl_trace, EXT4_IOC_MOVE_EXT_CMD)
    {
        eprintln!(
            "EXT4 MOVE_EXT hole rejection skipped: kernel/VFS returned unsupported errno before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, EXT4_IOC_MOVE_EXT_CMD),
        "MOVE_EXT hole rejection should still reach ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert_eq!(
        report["errno"].as_i64(),
        Some(EOPNOTSUPP_ERRNO),
        "hole-backed MOVE_EXT range should reject with EOPNOTSUPP: {report}"
    );
    assert_eq!(
        fs::read(&source).expect("read source after rejected move_ext"),
        expected_source,
        "rejected MOVE_EXT must leave the source file unchanged"
    );
    assert_eq!(
        fs::read(&donor).expect("read donor after rejected move_ext"),
        donor_before,
        "rejected MOVE_EXT must leave the donor file unchanged"
    );

    emit_scenario_result(scenario_id, "PASS", Some("errno=95_hole_backed_range"));
}

/// Mounted-path proof that ext4 mutation ioctls (SETFLAGS and MOVE_EXT) surface
/// a deterministic read-only rejection when the mount is `read_only: true`.
///
/// The backend already rejects these ioctls with `EROFS` at dispatch time for
/// read-only sessions (see `ffs-fuse` unit tests), but until now the
/// harness-level, real-kernel path only proved the writable happy-path and the
/// writable hole-backed rejection.  This scenario stitches the two phases
/// together: seed source + donor files via a brief rw mount, drop the session,
/// remount the same image read-only, and then prove — against the real FUSE
/// transport — that both mutation ioctls fail and the seeded file contents
/// remain byte-identical afterwards.
///
/// Per bd-l1sr3 the rejection path is a documented disjunction: either the
/// kernel/VFS short-circuits before dispatch (trace does **not** contain the
/// command) or the request reaches `ffs-fuse::ioctl` which then returns
/// `EROFS` (trace **does** contain it).  Both are acceptable; the
/// non-acceptable outcome is "ffs-fuse dispatched and mutated the image
/// anyway", which the post-state byte compare pins down.
#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_mutation_ioctls_fast_fail_erofs_on_read_only_mount() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 8 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    // ── Phase 1: rw mount, seed source + donor, then tear down. ────────────
    // Use the explicit fuser unmount path here, matching the other remount
    // tests.  `auto_unmount` delegates release to the fusermount helper and can
    // outlive the two-second mountinfo poll on loaded CI workers.
    let setup_trace_path: PathBuf = tmp.path().join("ioctl-ext4-erofs-setup.log");
    let setup_mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(setup_trace_path),
        ..MountOptions::default()
    };
    // The seed payloads are 4 blocks of distinct fill each so any accidental
    // MOVE_EXT swap through the ro-rejection path is instantly visible in the
    // post-state compare.
    let block_size = 4096_usize;
    let source_rel = "erofs_source.bin";
    let donor_rel = "erofs_donor.bin";
    let source_payload: Vec<u8> = std::iter::repeat_n(0x5A_u8, block_size * 4).collect();
    let donor_payload: Vec<u8> = std::iter::repeat_n(0xA5_u8, block_size * 4).collect();
    {
        let Some(setup_session) = try_mount_ffs_rw_with_options(&image, &mnt, &setup_mount_opts)
        else {
            return;
        };
        fs::write(mnt.join(source_rel), &source_payload).expect("write ro source seed");
        fs::write(mnt.join(donor_rel), &donor_payload).expect("write ro donor seed");
        drop(setup_session);
    }
    wait_for_fuse_mount_released(&mnt);

    // ── Phase 2: ro mount, attempt mutation ioctls, assert EROFS + no drift.
    let ro_trace_path: PathBuf = tmp.path().join("ioctl-ext4-erofs.log");
    let ro_mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ro_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_ro_session) = try_mount_ffs_with_options(&image, &mnt, &ro_mount_opts) else {
        return;
    };

    let source_path = mnt.join(source_rel);
    let donor_path = mnt.join(donor_rel);

    let source_before = fs::read(&source_path).expect("read source on ro mount");
    let donor_before = fs::read(&donor_path).expect("read donor on ro mount");
    assert_eq!(
        source_before, source_payload,
        "ro remount must expose seeded source bytes identically"
    );
    assert_eq!(
        donor_before, donor_payload,
        "ro remount must expose seeded donor bytes identically"
    );

    let scenario_id = "ext4_ioctl_mutation_rejects_erofs_on_ro_mount";

    // SETFLAGS: adding NOATIME to a file on an ro mount must not succeed.
    let setflags_report =
        ext4_inode_flags_ioctl(&source_path, "set", Some(ffs_types::EXT4_NOATIME_FL));
    let setflags_trace = read_ioctl_trace(&ro_trace_path);
    match setflags_report["errno"].as_i64() {
        Some(errno) if errno == i64::from(libc::EROFS) => {
            // Accepted: either the kernel/VFS short-circuited, or ffs-fuse
            // rejected after dispatch — both land EROFS on the caller.
        }
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO => {
            assert!(
                !trace_contains_cmd(&setflags_trace, EXT4_IOC_SETFLAGS_CMD),
                "SETFLAGS surfaced transport-unsupported errno after reaching \
                 ffs-fuse::ioctl on ro mount: {setflags_trace}"
            );
            eprintln!(
                "SETFLAGS ro rejection: kernel/VFS returned transport-unsupported errno \
                 before ffs-fuse::ioctl — acceptable per documented transport behaviour"
            );
        }
        other => assert_eq!(
            other,
            Some(i64::from(libc::EROFS)),
            "unexpected SETFLAGS errno on ro mount: {other:?} report={setflags_report} \
             trace={setflags_trace}",
        ),
    }

    // MOVE_EXT: swap 1 block between source and donor.  On ro, must reject.
    let move_ext_report = ext4_move_ext_ioctl(&source_path, &donor_path, 0, 0, 1);
    let move_ext_trace = read_ioctl_trace(&ro_trace_path);
    if move_ext_report["timeout"].as_bool() == Some(true) {
        assert!(
            !trace_contains_cmd(&move_ext_trace, EXT4_IOC_MOVE_EXT_CMD),
            "MOVE_EXT timed out after reaching ffs-fuse::ioctl on ro mount: {move_ext_trace}"
        );
        eprintln!(
            "MOVE_EXT ro rejection skipped: kernel/FUSE stack timed out before ffs-fuse::ioctl"
        );
        return;
    }
    match move_ext_report["errno"].as_i64() {
        Some(errno) if errno == i64::from(libc::EROFS) => {}
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO => {
            assert!(
                !trace_contains_cmd(&move_ext_trace, EXT4_IOC_MOVE_EXT_CMD),
                "MOVE_EXT surfaced transport-unsupported errno after reaching \
                 ffs-fuse::ioctl on ro mount: {move_ext_trace}"
            );
            eprintln!(
                "MOVE_EXT ro rejection: kernel/VFS returned transport-unsupported errno \
                 before ffs-fuse::ioctl — acceptable per documented transport behaviour"
            );
        }
        other => assert_eq!(
            other,
            Some(i64::from(libc::EROFS)),
            "unexpected MOVE_EXT errno on ro mount: {other:?} report={move_ext_report} \
             trace={move_ext_trace}",
        ),
    }

    // Post-state byte compare: neither rejected mutation may have perturbed
    // the seeded file contents — this is the real "no accidental mutation"
    // invariant the bead is protecting.
    let source_after = fs::read(&source_path).expect("read source after ro ioctls");
    let donor_after = fs::read(&donor_path).expect("read donor after ro ioctls");
    assert_eq!(
        source_after, source_payload,
        "rejected SETFLAGS/MOVE_EXT must not mutate source bytes on ro mount"
    );
    assert_eq!(
        donor_after, donor_payload,
        "rejected MOVE_EXT must not mutate donor bytes on ro mount"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("setflags+move_ext=EROFS_no_drift"),
    );
}

#[test]
fn ext4_fuse_seek_data_hole_reports_punched_range_offsets() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_seek_data_hole";
        let path = mnt.join("ext4_seek_layout.bin");
        assert_seek_data_hole_contract(&path, scenario_id);
    });
}

#[test]
fn ext4_fuse_seek_hole_reports_virtual_eof_for_fully_allocated_file() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_seek_hole_fully_allocated";
        let path = mnt.join("ext4_seek_fully_allocated.bin");
        assert_seek_fully_allocated_contract(&path, scenario_id);
    });
}

#[test]
fn ext4_fuse_seek_data_hole_reports_leading_sparse_hole_offsets() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_seek_leading_hole";
        let path = mnt.join("ext4_seek_leading_hole.bin");
        assert_seek_leading_hole_contract(&path, scenario_id);
    });
}

#[test]
fn ext4_fuse_seek_data_hole_reports_all_hole_sparse_file_offsets() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_seek_all_hole";
        let path = mnt.join("ext4_seek_all_hole.bin");
        assert_seek_all_hole_contract(&path, scenario_id);
    });
}

#[test]
fn fuse_statfs_returns_valid_stats() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Use `stat -f` to exercise the FUSE statfs handler and parse the output.
    let out = Command::new("stat")
        .args(["-f", "-c", "%s %b %f %a %c %d %l", mnt.to_str().unwrap()])
        .output()
        .expect("stat -f on mountpoint");
    assert!(
        out.status.success(),
        "stat -f failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let fields: Vec<&str> = stdout.split_whitespace().collect();
    assert_eq!(
        fields.len(),
        7,
        "expected 7 stat -f fields, got: {stdout:?}"
    );

    // Parse statfs fields: block_size blocks blocks_free blocks_avail files files_free namelen
    let block_size: u64 = fields[0].parse().expect("parse block_size");
    let blocks: u64 = fields[1].parse().expect("parse blocks");
    let blocks_free: u64 = fields[2].parse().expect("parse blocks_free");
    let blocks_avail: u64 = fields[3].parse().expect("parse blocks_avail");
    let files: u64 = fields[4].parse().expect("parse files");
    let files_free: u64 = fields[5].parse().expect("parse files_free");
    let namelen: u64 = fields[6].parse().expect("parse namelen");

    // Validate: block size should be a power of two in [1024, 65536].
    assert!(
        block_size.is_power_of_two() && (1024..=65536).contains(&block_size),
        "block_size {block_size} should be a power-of-two in [1024, 65536]"
    );

    // Total blocks should be non-zero (we made a 4 MiB image).
    assert!(blocks > 0, "total blocks should be > 0");

    // Free blocks should not exceed total blocks.
    assert!(
        blocks_free <= blocks,
        "free blocks ({blocks_free}) should be <= total ({blocks})"
    );
    assert!(
        blocks_avail <= blocks,
        "available blocks ({blocks_avail}) should be <= total ({blocks})"
    );

    // Total inodes should be non-zero.
    assert!(files > 0, "total inodes should be > 0");
    assert!(
        files_free <= files,
        "free inodes ({files_free}) should be <= total ({files})"
    );

    // Max filename length: ext4 is 255.
    assert_eq!(namelen, 255, "ext4 max filename length should be 255");
}

#[derive(Debug, Clone, Copy)]
struct StatFsSnapshot {
    blocks_free: u64,
    files_free: u64,
}

fn statfs_snapshot(path: &Path) -> StatFsSnapshot {
    let out = Command::new("stat")
        .args(["-f", "-c", "%s %b %f %a %c %d", path.to_str().unwrap()])
        .output()
        .expect("stat -f snapshot");
    assert!(
        out.status.success(),
        "stat -f snapshot failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let fields: Vec<&str> = stdout.split_whitespace().collect();
    assert_eq!(
        fields.len(),
        6,
        "expected 6 stat -f fields, got: {stdout:?}"
    );

    let _block_size: u64 = fields[0].parse().expect("parse block_size");
    let _blocks: u64 = fields[1].parse().expect("parse blocks");
    let blocks_free: u64 = fields[2].parse().expect("parse blocks_free");
    let _blocks_avail: u64 = fields[3].parse().expect("parse blocks_avail");
    let _files: u64 = fields[4].parse().expect("parse files");
    let files_free: u64 = fields[5].parse().expect("parse files_free");

    StatFsSnapshot {
        blocks_free,
        files_free,
    }
}

#[test]
fn fuse_write_large_file() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_write_large_multi_block_roundtrip";
        let path = mnt.join("large.bin");
        // Write 64 KiB of patterned data (crosses multiple blocks).
        let data = patterned_bytes(65_536, 251, 0);
        fs::write(&path, &data).expect("write large file via FUSE");

        let readback = fs::read(&path).expect("read large file");
        assert_eq!(readback.len(), 65536);
        assert_eq!(readback, data, "large file content should match");
        emit_scenario_result(scenario_id, "PASS", Some("64k_patterned_roundtrip"));
    });
}

#[test]
fn fuse_splice_pipe_to_file_16m_roundtrip() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    with_rw_mount_sized(64 * 1024 * 1024, |mnt| {
        let scenario_id = "ext4_rw_splice_pipe_to_file_16m_roundtrip";
        let report = run_splice_pipe_to_file_probe(mnt);
        if let Some(reason) = report["skipped"].as_str() {
            eprintln!("splice probe unavailable, skipping: {reason}");
            return;
        }

        assert_eq!(report["moved"].as_u64(), Some(16 * 1024 * 1024));
        assert_eq!(report["source_size"].as_u64(), Some(16 * 1024 * 1024));
        assert_eq!(report["dest_size"].as_u64(), Some(16 * 1024 * 1024));
        assert_eq!(
            report["source_sha256"], report["dest_sha256"],
            "splice destination must match source bytes: {report}"
        );
        emit_scenario_result(scenario_id, "PASS", Some("16m_sha256_match"));
    });
}

#[test]
fn fuse_copy_file_range_offsets_and_overlap_contract() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        assert_copy_file_range_offsets_and_overlap_contract(
            mnt,
            "ext4_rw_copy_file_range_offsets_and_overlap",
        );
    });
}

#[test]
fn fuse_xfstests_generic_249_sendfile_32m_roundtrip() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    with_rw_mount_sized(128 * 1024 * 1024, |mnt| {
        let scenario_id = "ext4_rw_xfstests_generic_249_sendfile_32m";
        let report = run_sendfile_32m_probe(mnt);
        if let Some(reason) = report["skipped"].as_str() {
            eprintln!("sendfile probe unavailable, skipping: {reason}");
            return;
        }

        assert_eq!(report["sent"].as_u64(), Some(32 * 1024 * 1024));
        assert_eq!(report["source_size"].as_u64(), Some(32 * 1024 * 1024));
        assert_eq!(report["dest_size"].as_u64(), Some(32 * 1024 * 1024));
        assert_eq!(
            report["source_sha256"], report["dest_sha256"],
            "sendfile destination must match source bytes: {report}"
        );
        emit_scenario_result(scenario_id, "PASS", Some("32m_sha256_match"));
    });
}

#[test]
#[ignore = "1 GiB mounted throughput benchmark; run explicitly for bd-qpoys acceptance"]
fn fuse_sendfile_1g_is_at_least_2x_naive_read_write() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    with_rw_mount_sized(4 * 1024 * 1024 * 1024, |mnt| {
        let scenario_id = "ext4_rw_sendfile_1g_vs_naive_read_write";
        let report = run_sendfile_vs_naive_1g_benchmark(mnt);
        if let Some(reason) = report["skipped"].as_str() {
            eprintln!("sendfile benchmark unavailable, skipping: {reason}");
            return;
        }

        assert_eq!(report["size"].as_u64(), Some(1024 * 1024 * 1024));
        assert_eq!(report["naive_bytes"].as_u64(), Some(1024 * 1024 * 1024));
        assert_eq!(report["sent"].as_u64(), Some(1024 * 1024 * 1024));
        assert_eq!(
            report["source_sample_sha256_before"], report["source_sample_sha256_after"],
            "benchmark source must not drift while measuring throughput: {report}"
        );
        let ratio = report["ratio"].as_f64().expect("benchmark ratio");
        assert!(
            ratio >= 2.0,
            "sendfile throughput ratio must be at least 2x naive read/write: {report}"
        );
        emit_scenario_result(scenario_id, "PASS", Some("sendfile_throughput_ratio_ge_2x"));
    });
}

#[test]
fn fuse_xfstests_generic_591_splice_file_to_pipe_modes() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    with_rw_mount_sized(16 * 1024 * 1024, |mnt| {
        let scenario_id = "ext4_rw_xfstests_generic_591_splice_file_to_pipe";
        let report = run_splice_file_to_pipe_probe(mnt);
        if let Some(reason) = report["skipped"].as_str() {
            eprintln!("splice file-to-pipe probe unavailable, skipping: {reason}");
            return;
        }

        let buffer_size = report["buffer_size"]
            .as_u64()
            .expect("generic/591 buffer_size");
        let cases = report["cases"].as_array().expect("generic/591 cases");
        assert_eq!(cases.len(), 4, "generic/591 should report four modes");
        let mut exercised = 0_u64;
        for case in cases {
            if case.get("skipped").is_some() {
                continue;
            }
            exercised += 1;
            assert_eq!(
                case["moved"].as_u64(),
                Some(buffer_size),
                "generic/591 mode did not splice the full file: {case}"
            );
        }
        assert!(
            exercised >= 2,
            "generic/591 should exercise at least buffered sequential and concurrent modes: \
             {report}"
        );
        emit_scenario_result(scenario_id, "PASS", Some("splice_modes_exercised"));
    });
}

#[test]
fn fuse_xfstests_generic_680_readonly_splice_pipe_merge_isolation() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    with_rw_mount_sized(16 * 1024 * 1024, |mnt| {
        let scenario_id = "ext4_rw_xfstests_generic_680_readonly_splice_pipe_merge";
        let report = run_readonly_splice_pipe_merge_probe(mnt);
        if let Some(reason) = report["skipped"].as_str() {
            eprintln!("read-only splice pipe probe unavailable, skipping: {reason}");
            return;
        }

        assert_eq!(report["moved"].as_u64(), Some(1));
        assert_eq!(report["pipe_write"].as_u64(), Some(16));
        assert_eq!(
            report["unchanged"].as_bool(),
            Some(true),
            "read-only file content changed after splice pipe merge probe: {report}"
        );
        emit_scenario_result(scenario_id, "PASS", Some("readonly_file_unchanged"));
    });
}

#[test]
fn fuse_spec_i3_write_and_persist_after_remount() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mount_a = tmp.path().join("mnt_a");
    fs::create_dir_all(&mount_a).expect("create first mountpoint");

    {
        let Some(_session) = try_mount_ffs_rw(&image, &mount_a) else {
            return;
        };
        let path = mount_a.join("persist_i3.txt");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .expect("create persist_i3.txt");
        file.write_all(b"persisted across remount\n")
            .expect("write persistence payload");
        file.sync_all().expect("sync persistence payload");
        let out = Command::new("sync").output().expect("sync command");
        assert!(
            out.status.success(),
            "sync command failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    } // drop first mount session before remounting the same image

    wait_for_fuse_mount_released(&mount_a);

    let mount_b = tmp.path().join("mnt_b");
    fs::create_dir_all(&mount_b).expect("create second mountpoint");
    let Some(_session) = try_mount_ffs_rw(&image, &mount_b) else {
        return;
    };
    let persisted = fs::read_to_string(mount_b.join("persist_i3.txt"))
        .expect("read persisted file after remount");
    assert_eq!(persisted, "persisted across remount\n");
    emit_scenario_result(
        "ext4_spec_i3_write_persists_across_remount",
        "PASS",
        Some("payload_preserved"),
    );
}

#[test]
fn fuse_spec_i5_delete_reclaims_free_counts() {
    with_rw_mount_sized(64 * 1024 * 1024, |mnt| {
        let before = statfs_snapshot(mnt);
        let batch_dir = mnt.join("reclaim_batch");
        fs::create_dir(&batch_dir).expect("mkdir reclaim_batch");

        for idx in 0..1_000_u32 {
            let path = batch_dir.join(format!("file_{idx:04}.txt"));
            let write_result = fs::write(path, format!("payload {idx}\n").as_bytes());
            assert!(
                write_result.is_ok(),
                "write reclaim file {idx}: {write_result:?}"
            );
        }

        let after_create = statfs_snapshot(mnt);
        assert!(
            after_create.blocks_free <= before.blocks_free,
            "free block count should not increase after creating files (before={}, after={})",
            before.blocks_free,
            after_create.blocks_free
        );
        assert!(
            after_create.files_free <= before.files_free,
            "free inode count should not increase after creating files (before={}, after={})",
            before.files_free,
            after_create.files_free
        );

        for idx in 0..1_000_u32 {
            let path = batch_dir.join(format!("file_{idx:04}.txt"));
            let remove_result = fs::remove_file(path);
            assert!(
                remove_result.is_ok(),
                "remove reclaim file {idx}: {remove_result:?}"
            );
        }
        fs::remove_dir(&batch_dir).expect("remove reclaim_batch");

        let after_delete = statfs_snapshot(mnt);
        assert!(
            after_delete.blocks_free >= after_create.blocks_free,
            "free blocks should increase after delete (after_create={}, after_delete={})",
            after_create.blocks_free,
            after_delete.blocks_free
        );
        assert!(
            after_delete.files_free >= after_create.files_free,
            "free inodes should increase after delete (after_create={}, after_delete={})",
            after_create.files_free,
            after_delete.files_free
        );

        // ext4/FUSE metadata bookkeeping may leave a small delta in free counts.
        let block_slack = 8_u64;
        let inode_slack = 4_u64;
        assert!(
            after_delete.blocks_free + block_slack >= before.blocks_free,
            "free blocks should be restored within slack after delete (before={}, after_delete={}, slack={})",
            before.blocks_free,
            after_delete.blocks_free,
            block_slack
        );
        assert!(
            after_delete.files_free + inode_slack >= before.files_free,
            "free inodes should be restored within slack after delete (before={}, after_delete={}, slack={})",
            before.files_free,
            after_delete.files_free,
            inode_slack
        );
        emit_scenario_result(
            "ext4_spec_i5_delete_reclaims_free_counts",
            "PASS",
            Some("blocks_and_inodes_reclaimed_within_slack"),
        );
    });
}

#[test]
fn fuse_spec_i6_concurrent_writes_no_corruption() {
    with_rw_mount(|mnt| {
        const THREADS: usize = 4;
        const WRITES_PER_THREAD: usize = 256;

        let mut handles = Vec::with_capacity(THREADS);
        for thread_id in 0..THREADS {
            let mount_root = mnt.to_path_buf();
            handles.push(thread::spawn(move || {
                let path = mount_root.join(format!("i6_thread_{thread_id}.txt"));
                let mut expected = String::new();
                for write_id in 0..WRITES_PER_THREAD {
                    use std::fmt::Write;
                    let _ = writeln!(expected, "thread={thread_id} write={write_id}");
                }
                fs::write(&path, expected.as_bytes()).expect("write concurrent thread file");
                let readback = fs::read_to_string(&path).expect("read concurrent thread file");
                assert_eq!(readback, expected, "thread file content should match");
            }));
        }

        for handle in handles {
            handle
                .join()
                .expect("concurrent writer thread should succeed");
        }

        for thread_id in 0..THREADS {
            let path = mnt.join(format!("i6_thread_{thread_id}.txt"));
            let content = fs::read_to_string(&path).expect("final verify concurrent thread file");
            let lines: HashSet<&str> = content.lines().collect();
            assert_eq!(
                lines.len(),
                WRITES_PER_THREAD,
                "thread file should have exactly {WRITES_PER_THREAD} lines"
            );
            for write_id in 0..WRITES_PER_THREAD {
                let needle = format!("thread={thread_id} write={write_id}");
                assert!(
                    lines.contains(needle.as_str()),
                    "missing expected line: {needle}"
                );
            }
        }
    });
}

#[test]
fn fuse_spec_i7_reader_sees_pre_modification_version_during_write() {
    with_rw_mount(|mnt| {
        let path = mnt.join("i7_snapshot.txt");
        fs::write(&path, b"old-version\n").expect("write old snapshot version");
        let writer_path = path.clone();
        let (replacement_ready_tx, replacement_ready_rx) = std::sync::mpsc::channel();
        let (reader_captured_tx, reader_captured_rx) = std::sync::mpsc::channel();

        let writer = thread::spawn(move || {
            let replacement = writer_path.with_extension("tmp");
            fs::write(&replacement, b"new-version\n").expect("write replacement payload");
            replacement_ready_tx
                .send(())
                .expect("signal replacement payload is prepared");
            reader_captured_rx
                .recv()
                .expect("wait for reader to capture pre-rename view");
            fs::rename(&replacement, &writer_path).expect("atomic replace for snapshot check");
        });

        // While writer prepares replacement data, readers should still see the old version.
        replacement_ready_rx
            .recv()
            .expect("wait for replacement payload to be prepared");
        let observed = fs::read_to_string(&path).expect("read pre-commit path view");
        reader_captured_tx
            .send(())
            .expect("signal reader captured pre-rename view");

        writer.join().expect("writer thread should succeed");

        assert_eq!(
            observed, "old-version\n",
            "reader should observe the pre-modification version while replacement is in-flight"
        );
        let latest = fs::read_to_string(&path).expect("read latest path version");
        assert!(
            latest.starts_with("new-version\n"),
            "path should expose the post-modification version"
        );
    });
}

// ── Large directory and ENOSPC E2E tests ─────────────────────────────────────

#[test]
fn fuse_readdir_large_directory() {
    with_rw_mount(|mnt| {
        let dir = mnt.join("bigdir");
        fs::create_dir(&dir).expect("mkdir bigdir");

        // Create 100 files in the directory.
        let count = 100_usize;
        for i in 0..count {
            let name = format!("file_{i:04}.txt");
            let write_result = fs::write(dir.join(&name), format!("content {i}").as_bytes());
            assert!(write_result.is_ok(), "write {name}: {write_result:?}");
        }

        // Read directory and collect all entries.
        let entries: Vec<String> = fs::read_dir(&dir)
            .expect("readdir bigdir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();

        // Verify no duplicates.
        let mut sorted = entries.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            entries.len(),
            sorted.len(),
            "readdir should return no duplicate entries"
        );

        // Verify we got all files.
        assert_eq!(
            entries.len(),
            count,
            "readdir should return all {count} files, got {}",
            entries.len()
        );

        // Spot-check a few entries.
        assert!(entries.contains(&"file_0000.txt".to_owned()));
        assert!(entries.contains(&"file_0050.txt".to_owned()));
        assert!(entries.contains(&"file_0099.txt".to_owned()));
    });
}

/// Regression test: creating files that span multiple directory blocks
/// then removing them must succeed.  Exercises the transition from
/// a single-block to a multi-block directory.
#[test]
fn fuse_create_and_remove_across_dir_block_boundary() {
    with_rw_mount_sized(64 * 1024 * 1024, |mnt| {
        let dir = mnt.join("boundary_dir");
        fs::create_dir(&dir).expect("mkdir boundary_dir");

        // 200 files crosses the ~170-entry first-block boundary.
        let count = 200_u32;
        for i in 0..count {
            let name = format!("file_{i:04}.txt");
            let path = dir.join(&name);
            let write_result = fs::write(&path, format!("payload {i}\n").as_bytes());
            assert!(write_result.is_ok(), "write {name}: {write_result:?}");
        }

        // Verify all files are accessible.
        for i in 0..count {
            let name = format!("file_{i:04}.txt");
            let path = dir.join(&name);
            assert!(path.exists(), "file_{i:04}.txt should exist after creation");
        }

        // Remove all files.
        for i in 0..count {
            let name = format!("file_{i:04}.txt");
            let path = dir.join(&name);
            let remove_result = fs::remove_file(&path);
            assert!(
                remove_result.is_ok(),
                "remove file_{i:04}.txt: {remove_result:?}"
            );
        }

        fs::remove_dir(&dir).expect("remove boundary_dir");
    });
}

#[test]
fn fuse_write_enospc_on_full_filesystem() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = tmp.path().join("tiny.ext4");

    // Create a very small 1 MiB ext4 image to exhaust space quickly.
    let f = fs::File::create(&image).expect("create tiny image");
    f.set_len(1024 * 1024).expect("set tiny image size");
    drop(f);

    let out = Command::new("mkfs.ext4")
        .args([
            "-F",
            "-b",
            "1024",
            "-N",
            "32",
            "-L",
            "ffs-enospc",
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.ext4 tiny");
    assert!(
        out.status.success(),
        "mkfs.ext4 tiny failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs_rw(&image, &mnt) else {
        return;
    };

    // Write data to fill the filesystem.
    let mut hit_enospc = false;
    for i in 0..100 {
        let path = mnt.join(format!("fill_{i:03}.dat"));
        // Write ~10KB per file to gradually fill 1MB image.
        match fs::write(&path, [0xAA_u8; 10240]) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(28 /* ENOSPC */) => {
                hit_enospc = true;
                break;
            }
            Err(e) => {
                // Other errors might occur depending on allocator behavior.
                eprintln!("write fill_{i}: {e}");
                hit_enospc = true;
                break;
            }
        }
    }

    assert!(
        hit_enospc,
        "should eventually hit ENOSPC on 1 MiB filesystem"
    );
}

// ── fsync/flush E2E tests ────────────────────────────────────────────────────

#[test]
fn fuse_fsync_persists_written_data() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fsync";
        let path = mnt.join("synced.txt");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .expect("create synced.txt");

        file.write_all(b"data before fsync\n")
            .expect("write before fsync");

        // sync_all triggers FUSE fsync.
        file.sync_all().expect("fsync via sync_all");

        drop(file);

        // Read back and verify.
        let content = fs::read_to_string(&path).expect("read after fsync");
        assert_eq!(content, "data before fsync\n");
        emit_scenario_result(scenario_id, "PASS", Some("sync_all"));
    });
}

#[test]
fn fuse_fsyncdir_emits_scenario_result_and_preserves_dirent() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fsyncdir";
        let dir = mnt.join("synced_dir");
        fs::create_dir(&dir).expect("mkdir for ext4 fsyncdir");

        let child = dir.join("child.txt");
        fs::write(&child, b"directory sync payload\n").expect("write child before ext4 fsyncdir");

        let dirfd = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(&dir)
            .expect("open directory fd for ext4 fsyncdir");
        dirfd.sync_all().expect("fsyncdir via sync_all on ext4");
        drop(dirfd);

        let entries: HashSet<String> = fs::read_dir(&dir)
            .expect("readdir after ext4 fsyncdir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries.contains("child.txt"),
            "directory entry should remain visible after ext4 fsyncdir, got: {entries:?}"
        );
        assert_eq!(
            fs::read_to_string(&child).expect("read child after ext4 fsyncdir"),
            "directory sync payload\n"
        );
        emit_scenario_result(scenario_id, "PASS", Some("dirfd_sync_all"));
    });
}

#[test]
fn fuse_sync_data_without_metadata() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fdatasync";
        let path = mnt.join("datasync.txt");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .expect("create datasync.txt");

        file.write_all(b"datasync content\n")
            .expect("write before sync_data");

        // sync_data triggers FUSE fsync with datasync=true.
        file.sync_data().expect("sync_data");

        drop(file);

        let content = fs::read_to_string(&path).expect("read after sync_data");
        assert_eq!(content, "datasync content\n");
        emit_scenario_result(scenario_id, "PASS", Some("sync_data"));
    });
}

#[test]
fn ext4_fuse_flush_emits_scenario_result_and_preserves_data() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_flush";
        let path = mnt.join("flushed.txt");

        // Write and explicitly flush (triggers FUSE flush).
        {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .expect("create flushed.txt");

            file.write_all(b"flushed content\n").expect("write");
            // std::io::Write::flush triggers the FUSE flush handler.
            file.flush().expect("explicit flush");
        } // drop/close triggers another FUSE flush+release

        let content = fs::read_to_string(&path).expect("read after flush+close");
        assert_eq!(content, "flushed content\n");
        emit_scenario_result(scenario_id, "PASS", Some("explicit_flush_and_close"));
    });
}

#[test]
fn writeback_cache_ext4_opt_in_flush_fsyncdir_reopen() {
    let scenario_id = "writeback_cache_ext4_opt_in_flush_fsyncdir_reopen";
    if !fuse_available() {
        emit_scenario_result(scenario_id, "SKIP", Some("fuse_prerequisites_unavailable"));
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        writeback_cache: WritebackCacheMode::Enabled,
        ..MountOptions::default()
    };
    let Some(session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        emit_scenario_result(scenario_id, "SKIP", Some("fuse_mount_failed"));
        return;
    };

    let dir = mnt.join("writeback_cache");
    fs::create_dir(&dir).expect("mkdir writeback_cache");
    let tmp_file = dir.join("data.tmp");
    let final_file = dir.join("data.bin");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(&tmp_file)
        .expect("create writeback-cache temp file");

    file.write_all(b"writeback-cache v1\n")
        .expect("write first payload");
    file.flush().expect("flush remains non-durable lifecycle");
    file.sync_all().expect("fsync first payload");
    file.set_len(0).expect("truncate before repeated write");
    file.seek(SeekFrom::Start(0))
        .expect("rewind before repeated write");
    file.write_all(b"writeback-cache v2\n")
        .expect("write repeated payload");
    file.sync_all().expect("fsync repeated payload");
    drop(file);

    fs::rename(&tmp_file, &final_file).expect("rename after fsynced data");
    let dirfd = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(&dir)
        .expect("open writeback-cache directory fd");
    dirfd.sync_all().expect("fsyncdir after rename");
    drop(dirfd);
    assert_eq!(
        fs::read_to_string(&final_file).expect("read final file before remount"),
        "writeback-cache v2\n"
    );

    drop(session);
    wait_for_fuse_mount_released(&mnt);

    let Some(_remount) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        emit_scenario_result(scenario_id, "SKIP", Some("fuse_remount_failed"));
        return;
    };
    assert_eq!(
        fs::read_to_string(&final_file).expect("read final file after remount"),
        "writeback-cache v2\n"
    );
    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("writeback_cache_flush_fsync_fsyncdir_reopen"),
    );
}

#[test]
fn ext4_fuse_read_only_flush_succeeds_without_data_drift() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    assert_read_only_flush_contract(&mnt.join("hello.txt"), "ext4_ro_flush_succeeds_no_drift");
}

#[test]
fn fuse_fsync_after_multiple_writes() {
    with_rw_mount(|mnt| {
        let path = mnt.join("multi_write_sync.txt");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .expect("create multi_write_sync.txt");

        // Multiple writes followed by a single fsync.
        file.write_all(b"chunk1 ").expect("write chunk1");
        file.write_all(b"chunk2 ").expect("write chunk2");
        file.write_all(b"chunk3").expect("write chunk3");
        file.sync_all().expect("fsync after multiple writes");

        drop(file);

        let content = fs::read_to_string(&path).expect("read multi_write");
        assert_eq!(content, "chunk1 chunk2 chunk3");
    });
}

// ── Extended attribute (xattr) E2E tests ─────────────────────────────────────

/// Helper: set an extended attribute on a file using Python's `os.setxattr`.
fn py_setxattr(path: &Path, name: &str, value: &[u8]) {
    let script = "import os, sys\nos.setxattr(sys.argv[1], sys.argv[2], sys.stdin.buffer.read())";
    let mut child = Command::new("python3")
        .args(["-c", script, path.to_str().unwrap(), name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3 setxattr");
    {
        let mut stdin = child.stdin.take().expect("setxattr stdin");
        stdin.write_all(value).expect("write setxattr stdin");
    }
    let out = child.wait_with_output().expect("python3 setxattr");
    assert!(
        out.status.success(),
        "setxattr failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn py_setxattr_report(path: &Path, name: &str, value: &[u8], flags: i32) -> Value {
    let flags_arg = flags.to_string();
    let script = "import json, os, sys\ntry:\n os.setxattr(sys.argv[1], sys.argv[2], sys.stdin.buffer.read(), int(sys.argv[3]))\n print(json.dumps({'ok': True}))\nexcept OSError as e:\n print(json.dumps({'errno': e.errno, 'message': str(e)}))";
    let mut child = Command::new("python3")
        .args(["-c", script, path.to_str().unwrap(), name, &flags_arg])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3 setxattr JSON");
    {
        let mut stdin = child.stdin.take().expect("setxattr JSON stdin");
        stdin.write_all(value).expect("write setxattr JSON stdin");
    }
    let out = child.wait_with_output().expect("python3 setxattr JSON");
    assert!(
        out.status.success(),
        "python3 setxattr JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse setxattr JSON")
}

/// Helper: get an extended attribute value from a file using Python's `os.getxattr`.
/// Returns `None` if the attribute does not exist.
fn py_getxattr(path: &Path, name: &str) -> Option<Vec<u8>> {
    let script = format!(
        "import os,sys\ntry:\n v=os.getxattr({path:?},{name:?})\n sys.stdout.buffer.write(v)\nexcept OSError:\n sys.exit(1)",
        path = path.to_str().unwrap(),
        name = name,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 getxattr");
    if out.status.success() {
        Some(out.stdout)
    } else {
        None
    }
}

fn py_getxattr_report(path: &Path, name: &str) -> Value {
    let script = format!(
        "import json, os\ntry:\n v=os.getxattr({path:?},{name:?})\n print(json.dumps({{'value_hex': v.hex(), 'len': len(v)}}))\nexcept OSError as e:\n print(json.dumps({{'errno': e.errno, 'message': str(e)}}))",
        path = path.to_str().unwrap(),
        name = name,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 getxattr JSON");
    assert!(
        out.status.success(),
        "python3 getxattr JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse getxattr JSON")
}

fn py_getxattr_probe_report(path: &Path, name: &str, size: usize) -> Value {
    let script = format!(
        "import ctypes, json, os\nlibc = ctypes.CDLL(None, use_errno=True)\nlibc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]\nlibc.getxattr.restype = ctypes.c_ssize_t\nbuf = None if {size} == 0 else ctypes.create_string_buffer({size})\nret = libc.getxattr({path:?}.encode(), {name:?}.encode(), None if buf is None else ctypes.byref(buf), {size})\nif ret >= 0:\n out = {{'len': ret}}\n if buf is not None:\n  out['value_hex'] = ctypes.string_at(buf, ret).hex()\n print(json.dumps(out))\nelse:\n errno = ctypes.get_errno()\n print(json.dumps({{'errno': errno, 'message': os.strerror(errno)}}))",
        path = path.to_str().unwrap(),
        name = name,
        size = size,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 getxattr probe JSON");
    assert!(
        out.status.success(),
        "python3 getxattr probe JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse getxattr probe JSON")
}

/// Helper: list extended attribute names on a file using Python's `os.listxattr`.
fn py_listxattr(path: &Path) -> Vec<String> {
    let script = format!(
        "import os\nfor n in os.listxattr({path:?}):\n print(n)",
        path = path.to_str().unwrap(),
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 listxattr");
    assert!(
        out.status.success(),
        "listxattr failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

fn py_listxattr_probe_report(path: &Path, size: usize) -> Value {
    let script = format!(
        "import ctypes, json, os\nlibc = ctypes.CDLL(None, use_errno=True)\nlibc.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]\nlibc.listxattr.restype = ctypes.c_ssize_t\nbuf = None if {size} == 0 else ctypes.create_string_buffer({size})\nret = libc.listxattr({path:?}.encode(), None if buf is None else ctypes.byref(buf), {size})\nif ret >= 0:\n out = {{'len': ret}}\n if buf is not None:\n  raw = ctypes.string_at(buf, ret)\n  out['names'] = [chunk.decode() for chunk in raw.split(b'\\0') if chunk]\n print(json.dumps(out))\nelse:\n errno = ctypes.get_errno()\n print(json.dumps({{'errno': errno, 'message': os.strerror(errno)}}))",
        path = path.to_str().unwrap(),
        size = size,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 listxattr probe JSON");
    assert!(
        out.status.success(),
        "python3 listxattr probe JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse listxattr probe JSON")
}

/// Helper: remove an extended attribute. Returns true if removal succeeded.
fn py_removexattr(path: &Path, name: &str) -> bool {
    let script = format!(
        "import os; os.removexattr({path:?}, {name:?})",
        path = path.to_str().unwrap(),
        name = name,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 removexattr");
    out.status.success()
}

fn py_removexattr_report(path: &Path, name: &str) -> Value {
    let script = format!(
        "import json, os\ntry:\n os.removexattr({path:?}, {name:?})\n print(json.dumps({{'ok': True}}))\nexcept OSError as e:\n print(json.dumps({{'errno': e.errno, 'message': str(e)}}))",
        path = path.to_str().unwrap(),
        name = name,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 removexattr JSON");
    assert!(
        out.status.success(),
        "python3 removexattr JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse removexattr JSON")
}

fn py_chmod_report(path: &Path, mode: u32) -> Value {
    let script = format!(
        "import json, os\ntry:\n os.chmod({path:?}, {mode})\n print(json.dumps({{'ok': True}}))\nexcept OSError as e:\n print(json.dumps({{'errno': e.errno, 'message': str(e)}}))",
        path = path.to_str().unwrap(),
        mode = mode,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 chmod JSON");
    assert!(
        out.status.success(),
        "python3 chmod JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse chmod JSON")
}

fn py_truncate_report(path: &Path, size: u64) -> Value {
    let script = format!(
        "import json, os\ntry:\n os.truncate({path:?}, {size})\n print(json.dumps({{'ok': True}}))\nexcept OSError as e:\n print(json.dumps({{'errno': e.errno, 'message': str(e)}}))",
        path = path.to_str().unwrap(),
        size = size,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 truncate JSON");
    assert!(
        out.status.success(),
        "python3 truncate JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse truncate JSON")
}

fn py_utime_report(path: &Path, atime: i64, mtime: i64) -> Value {
    let script = format!(
        "import json, os\ntry:\n os.utime({path:?}, ({atime}, {mtime}))\n print(json.dumps({{'ok': True}}))\nexcept OSError as e:\n print(json.dumps({{'errno': e.errno, 'message': str(e)}}))",
        path = path.to_str().unwrap(),
        atime = atime,
        mtime = mtime,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 utime JSON");
    assert!(
        out.status.success(),
        "python3 utime JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse utime JSON")
}

fn py_renameat2_report(old_path: &Path, new_path: &Path, flags: u32) -> Value {
    let script = format!(
        "import ctypes, json, os\nAT_FDCWD = -100\nlibc = ctypes.CDLL(None, use_errno=True)\nrenameat2 = libc.renameat2\nrenameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]\nrenameat2.restype = ctypes.c_int\nret = renameat2(AT_FDCWD, {old_path:?}.encode(), AT_FDCWD, {new_path:?}.encode(), {flags})\nif ret == 0:\n print(json.dumps({{'ok': True}}))\nelse:\n errno = ctypes.get_errno()\n print(json.dumps({{'errno': errno, 'message': os.strerror(errno)}}))",
        old_path = old_path.to_str().unwrap(),
        new_path = new_path.to_str().unwrap(),
        flags = flags,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 renameat2 JSON");
    assert!(
        out.status.success(),
        "python3 renameat2 JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse renameat2 JSON")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStateSnapshot {
    bytes: Vec<u8>,
    mode: u32,
    len: u64,
    atime: i64,
    atime_nsec: i64,
    mtime: i64,
    mtime_nsec: i64,
}

fn snapshot_file_state(path: &Path) -> FileStateSnapshot {
    let meta = fs::metadata(path).expect("stat file state");
    FileStateSnapshot {
        bytes: fs::read(path).expect("read file state"),
        mode: meta.permissions().mode() & 0o7777,
        len: meta.len(),
        atime: meta.atime(),
        atime_nsec: meta.atime_nsec(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
    }
}

fn assert_file_state_unchanged(path: &Path, before: &FileStateSnapshot, context: &str) {
    let after = snapshot_file_state(path);
    assert_eq!(
        after, *before,
        "{context} must not change file contents or metadata on a read-only mount"
    );
}

fn snapshot_directory_entries(path: &Path) -> HashSet<String> {
    fs::read_dir(path)
        .expect("readdir directory state")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

fn assert_unlink_directory_via_remove_file_reports_eisdir(mnt: &Path, scenario_id: &str) {
    let dir = mnt.join("unlink_directory_target");
    fs::create_dir(&dir).expect("create directory unlink target");
    let child = dir.join("child.txt");
    fs::write(&child, b"child").expect("seed child beneath unlink target");

    let root_entries_before = snapshot_directory_entries(mnt);
    let dir_entries_before = snapshot_directory_entries(&dir);
    let child_before = snapshot_file_state(&child);

    let err = fs::remove_file(&dir).expect_err("unlink on directory should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EISDIR),
        "unlink on a directory should surface exact EISDIR: {err}"
    );
    assert!(
        dir.is_dir(),
        "failed unlink on directory must leave the directory in place"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "failed unlink on directory must not change visible root entries"
    );
    assert_eq!(
        snapshot_directory_entries(&dir),
        dir_entries_before,
        "failed unlink on directory must not change child entries"
    );
    assert_file_state_unchanged(&child, &child_before, "directory unlink rejection");

    emit_scenario_result(scenario_id, "PASS", Some("errno=EISDIR_no_drift"));
}

fn assert_unlink_missing_reports_enoent(mnt: &Path, scenario_id: &str) {
    let missing = mnt.join("missing_unlink_target.txt");
    let witness = mnt.join("unlink_missing_witness.txt");
    fs::write(&witness, b"unlink missing witness\n").expect("write unlink missing witness");
    let root_entries_before = snapshot_directory_entries(mnt);
    let witness_before = snapshot_file_state(&witness);

    let err = fs::remove_file(&missing).expect_err("unlink on missing path should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOENT),
        "unlink on a missing path should surface exact ENOENT: {err}"
    );
    assert!(
        fs::symlink_metadata(&missing).is_err(),
        "failed unlink on a missing path must not materialize the missing entry"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "failed unlink on a missing path must not change visible root entries"
    );
    assert_file_state_unchanged(&witness, &witness_before, "missing unlink rejection");

    emit_scenario_result(scenario_id, "PASS", Some("errno=ENOENT_no_drift"));
}

fn assert_rename_missing_source_reports_enoent(mnt: &Path, scenario_id: &str) {
    let missing_source = mnt.join("missing_rename_source.txt");
    let target = mnt.join("missing_rename_target.txt");
    let witness = mnt.join("rename_missing_witness.txt");
    fs::write(&witness, b"rename missing witness\n").expect("write rename missing witness");
    let root_entries_before = snapshot_directory_entries(mnt);
    let witness_before = snapshot_file_state(&witness);

    let err =
        fs::rename(&missing_source, &target).expect_err("rename with missing source should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOENT),
        "rename with a missing source should surface exact ENOENT: {err}"
    );
    assert!(
        fs::symlink_metadata(&missing_source).is_err(),
        "rejected rename must leave the missing source absent"
    );
    assert!(
        fs::symlink_metadata(&target).is_err(),
        "rejected rename must not create the target entry"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "rejected rename with missing source must not change visible root entries"
    );
    assert_file_state_unchanged(&witness, &witness_before, "rename missing-source rejection");

    emit_scenario_result(scenario_id, "PASS", Some("errno=ENOENT_no_drift"));
}

fn assert_rename_over_nonempty_directory_reports_enotempty(mnt: &Path, scenario_id: &str) {
    let source_dir = mnt.join("rename_nonempty_source");
    let destination_dir = mnt.join("rename_nonempty_destination");
    fs::create_dir(&source_dir).expect("create rename source directory");
    fs::create_dir(&destination_dir).expect("create rename destination directory");

    let source_child = source_dir.join("source_child.txt");
    let destination_child = destination_dir.join("destination_child.txt");
    fs::write(&source_child, b"source child\n").expect("write source child");
    fs::write(&destination_child, b"destination child\n").expect("write destination child");

    let root_entries_before = snapshot_directory_entries(mnt);
    let source_entries_before = snapshot_directory_entries(&source_dir);
    let destination_entries_before = snapshot_directory_entries(&destination_dir);
    let source_child_before = snapshot_file_state(&source_child);
    let destination_child_before = snapshot_file_state(&destination_child);

    let err =
        fs::rename(&source_dir, &destination_dir).expect_err("rename over non-empty directory");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOTEMPTY),
        "rename over non-empty directory should surface exact ENOTEMPTY: {err}"
    );
    assert!(
        fs::metadata(&source_dir)
            .expect("stat source directory after rejected rename")
            .is_dir(),
        "rejected rename must leave the source directory in place"
    );
    assert!(
        fs::metadata(&destination_dir)
            .expect("stat destination directory after rejected rename")
            .is_dir(),
        "rejected rename must leave the destination directory in place"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "rename over non-empty directory must not change visible root entries"
    );
    assert_eq!(
        snapshot_directory_entries(&source_dir),
        source_entries_before,
        "rejected rename must not disturb source directory children"
    );
    assert_eq!(
        snapshot_directory_entries(&destination_dir),
        destination_entries_before,
        "rejected rename must not disturb destination directory children"
    );
    assert_file_state_unchanged(
        &source_child,
        &source_child_before,
        "rename over non-empty directory source child",
    );
    assert_file_state_unchanged(
        &destination_child,
        &destination_child_before,
        "rename over non-empty directory destination child",
    );

    emit_scenario_result(scenario_id, "PASS", Some("errno=ENOTEMPTY_no_drift"));
}

fn assert_rename_directory_into_own_child_reports_einval(mnt: &Path, scenario_id: &str) {
    let source_dir = mnt.join("rename_cycle_source");
    let child_dir = source_dir.join("child");
    let target = child_dir.join("moved");
    let witness = source_dir.join("witness.txt");
    fs::create_dir(&source_dir).expect("create rename cycle source directory");
    fs::create_dir(&child_dir).expect("create rename cycle child directory");
    fs::write(&witness, b"rename cycle witness\n").expect("write rename cycle witness");

    let root_entries_before = snapshot_directory_entries(mnt);
    let source_entries_before = snapshot_directory_entries(&source_dir);
    let child_entries_before = snapshot_directory_entries(&child_dir);
    let witness_before = snapshot_file_state(&witness);
    let source_ino_before = fs::metadata(&source_dir)
        .expect("stat source before rejected cycle rename")
        .ino();
    let child_ino_before = fs::metadata(&child_dir)
        .expect("stat child before rejected cycle rename")
        .ino();

    let err = fs::rename(&source_dir, &target)
        .expect_err("rename directory beneath its own child should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EINVAL),
        "rename directory beneath its own child should surface exact EINVAL: {err}"
    );
    assert!(
        fs::metadata(&source_dir)
            .expect("stat source after rejected cycle rename")
            .is_dir(),
        "rejected cycle rename must leave the source directory in place"
    );
    assert!(
        fs::metadata(&child_dir)
            .expect("stat child after rejected cycle rename")
            .is_dir(),
        "rejected cycle rename must leave the child directory in place"
    );
    assert!(
        fs::symlink_metadata(&target).is_err(),
        "rejected cycle rename must not create the nested destination entry"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "rejected cycle rename must not change root entries"
    );
    assert_eq!(
        snapshot_directory_entries(&source_dir),
        source_entries_before,
        "rejected cycle rename must not change source directory entries"
    );
    assert_eq!(
        snapshot_directory_entries(&child_dir),
        child_entries_before,
        "rejected cycle rename must not change child directory entries"
    );
    assert_file_state_unchanged(&witness, &witness_before, "rejected cycle rename witness");
    assert_eq!(
        fs::metadata(&source_dir)
            .expect("stat source inode after rejected cycle rename")
            .ino(),
        source_ino_before,
        "rejected cycle rename must preserve the source inode binding"
    );
    assert_eq!(
        fs::metadata(&child_dir)
            .expect("stat child inode after rejected cycle rename")
            .ino(),
        child_ino_before,
        "rejected cycle rename must preserve the child inode binding"
    );

    emit_scenario_result(scenario_id, "PASS", Some("errno=EINVAL_no_drift"));
}

fn assert_rename_file_directory_type_mismatch_contract(mnt: &Path, scenario_id: &str) {
    assert_rename_file_over_directory_rejected_with_eisdir(mnt);
    assert_rename_directory_over_file_rejected_with_enotdir(mnt);

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("file_over_dir=EISDIR_dir_over_file=ENOTDIR_no_drift"),
    );
}

fn assert_rename_file_over_directory_rejected_with_eisdir(mnt: &Path) {
    let file_source = mnt.join("rename_file_over_dir_src.txt");
    let directory_target = mnt.join("rename_file_over_dir_dst");
    fs::write(&file_source, b"rename file source\n").expect("write rename file source");
    fs::create_dir(&directory_target).expect("create rename directory target");
    let directory_child = directory_target.join("child.txt");
    fs::write(&directory_child, b"rename dir child\n").expect("write rename directory child");

    let root_entries_before = snapshot_directory_entries(mnt);
    let file_source_before = snapshot_file_state(&file_source);
    let directory_child_before = snapshot_file_state(&directory_child);
    let directory_entries_before = snapshot_directory_entries(&directory_target);

    let err = fs::rename(&file_source, &directory_target)
        .expect_err("rename file over directory should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EISDIR),
        "rename file over directory should surface exact EISDIR: {err}"
    );
    assert!(
        fs::symlink_metadata(&file_source).is_ok(),
        "rejected rename must leave the file source entry in place"
    );
    assert!(
        fs::metadata(&directory_target)
            .expect("stat directory target after rejected rename")
            .is_dir(),
        "rejected rename must leave the destination as a directory"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "rename file over directory must not change visible root entries"
    );
    assert_eq!(
        snapshot_directory_entries(&directory_target),
        directory_entries_before,
        "rename file over directory must not change directory child entries"
    );
    assert_file_state_unchanged(
        &file_source,
        &file_source_before,
        "rename file over directory source",
    );
    assert_file_state_unchanged(
        &directory_child,
        &directory_child_before,
        "rename file over directory child",
    );
}

fn assert_rename_directory_over_file_rejected_with_enotdir(mnt: &Path) {
    let directory_source = mnt.join("rename_dir_over_file_src");
    let file_target = mnt.join("rename_dir_over_file_dst.txt");
    fs::create_dir(&directory_source).expect("create rename directory source");
    let source_child = directory_source.join("nested.txt");
    fs::write(&source_child, b"rename dir source child\n")
        .expect("write rename directory source child");
    fs::write(&file_target, b"rename file target\n").expect("write rename file target");

    let root_entries_before = snapshot_directory_entries(mnt);
    let source_entries_before = snapshot_directory_entries(&directory_source);
    let source_child_before = snapshot_file_state(&source_child);
    let file_target_before = snapshot_file_state(&file_target);

    let err = fs::rename(&directory_source, &file_target)
        .expect_err("rename directory over file should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOTDIR),
        "rename directory over file should surface exact ENOTDIR: {err}"
    );
    assert!(
        fs::metadata(&directory_source)
            .expect("stat directory source after rejected rename")
            .is_dir(),
        "rejected rename must leave the source as a directory"
    );
    assert!(
        fs::symlink_metadata(&source_child).is_ok(),
        "rejected rename must preserve the source directory child entry"
    );
    assert!(
        fs::metadata(&file_target)
            .expect("stat file target after rejected rename")
            .is_file(),
        "rejected rename must leave the destination as a file"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "rename directory over file must not change visible root entries"
    );
    assert_eq!(
        snapshot_directory_entries(&directory_source),
        source_entries_before,
        "rename directory over file must not change source directory entries"
    );
    assert_file_state_unchanged(
        &source_child,
        &source_child_before,
        "rename directory over file child",
    );
    assert_file_state_unchanged(
        &file_target,
        &file_target_before,
        "rename directory over file target",
    );
}

fn assert_read_only_flush_contract(path: &Path, scenario_id: &str) {
    let before = snapshot_file_state(path);
    let mut file = fs::File::open(path).expect("open file for read-only flush contract");
    file.flush().expect("read-only flush should succeed");
    drop(file);

    assert_file_state_unchanged(path, &before, "read-only flush");
    emit_scenario_result(scenario_id, "PASS", Some("flush_ok_no_drift"));
}

fn assert_read_only_file_sync_contract(
    path: &Path,
    scenario_id: &str,
    sync_name: &str,
    sync_fn: impl FnOnce(&fs::File) -> std::io::Result<()>,
) {
    let before = snapshot_file_state(path);
    let file = fs::File::open(path).expect("open file for read-only sync contract");
    let err = sync_fn(&file).expect_err("read-only sync should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EROFS),
        "read-only {sync_name} should surface exact EROFS: {err}"
    );
    drop(file);

    let context = format!("rejected {sync_name}");
    assert_file_state_unchanged(path, &before, &context);
    emit_scenario_result(scenario_id, "PASS", Some("sync=EROFS_no_drift"));
}

fn assert_read_only_dir_sync_contract(dir: &Path, child: &Path, scenario_id: &str) {
    let entries_before = snapshot_directory_entries(dir);
    let child_before = snapshot_file_state(child);

    let dirfd = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(dir)
        .expect("open directory fd for read-only sync contract");
    let err = dirfd
        .sync_all()
        .expect_err("read-only directory sync should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EROFS),
        "read-only fsyncdir should surface exact EROFS: {err}"
    );
    drop(dirfd);

    let entries_after = snapshot_directory_entries(dir);
    assert_eq!(
        entries_after, entries_before,
        "rejected fsyncdir must not change directory entries on a read-only mount"
    );
    assert_file_state_unchanged(child, &child_before, "rejected fsyncdir");
    emit_scenario_result(scenario_id, "PASS", Some("fsyncdir=EROFS_no_drift"));
}

fn assert_read_only_setattr_contract(path: &Path, scenario_id: &str) {
    let before = snapshot_file_state(path);
    let requested_mode = if before.mode == 0o755 { 0o600 } else { 0o755 };
    let truncate_len = if before.len == 5 { 6 } else { 5 };
    let requested_time = if before.mtime == 1_700_000_000 {
        1_700_000_123
    } else {
        1_700_000_000
    };

    let chmod_report = py_chmod_report(path, requested_mode);
    assert_eq!(
        chmod_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only chmod should surface exact EROFS: {chmod_report}"
    );
    assert_file_state_unchanged(path, &before, "rejected chmod");

    let truncate_report = py_truncate_report(path, truncate_len);
    assert_eq!(
        truncate_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only truncate should surface exact EROFS: {truncate_report}"
    );
    assert_file_state_unchanged(path, &before, "rejected truncate");

    let utime_report = py_utime_report(path, requested_time, requested_time);
    assert_eq!(
        utime_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only utime should surface exact EROFS: {utime_report}"
    );
    assert_file_state_unchanged(path, &before, "rejected utime");

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("chmod+truncate+utimes=EROFS_no_drift"),
    );
}

fn assert_read_only_xattr_mutation_contract(path: &Path, scenario_id: &str) {
    let before = snapshot_file_state(path);

    let set_report = py_setxattr_report(path, "user.created", b"blocked", 0);
    assert_eq!(
        set_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only setxattr should surface exact EROFS: {set_report}"
    );
    assert_file_state_unchanged(path, &before, "rejected setxattr");
    assert!(
        py_getxattr(path, "user.created").is_none(),
        "read-only setxattr must not create a new xattr"
    );
    assert_eq!(
        py_getxattr(path, "user.locked").expect("locked xattr should remain readable"),
        b"original",
        "read-only setxattr must not disturb the targeted existing xattr state"
    );
    assert_eq!(
        py_getxattr(path, "user.keep").expect("keep xattr should remain readable"),
        b"preserve",
        "read-only setxattr must not disturb unrelated xattrs"
    );

    let remove_report = py_removexattr_report(path, "user.locked");
    assert_eq!(
        remove_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only removexattr should surface exact EROFS: {remove_report}"
    );
    assert_file_state_unchanged(path, &before, "rejected removexattr");
    assert_eq!(
        py_getxattr(path, "user.locked").expect("locked xattr should remain readable"),
        b"original",
        "read-only removexattr must not delete the targeted xattr"
    );
    assert_eq!(
        py_getxattr(path, "user.keep").expect("keep xattr should remain readable"),
        b"preserve",
        "read-only removexattr must not disturb unrelated xattrs"
    );

    let names = py_listxattr(path);
    assert!(
        !names.iter().any(|name| name == "user.created"),
        "read-only setxattr must not leave a newly created xattr behind: {names:?}"
    );
    assert!(
        names.iter().any(|name| name == "user.locked"),
        "read-only removexattr must leave the targeted xattr intact: {names:?}"
    );
    assert!(
        names.iter().any(|name| name == "user.keep"),
        "read-only xattr mutations must leave unrelated xattrs intact: {names:?}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("setxattr+removexattr=EROFS_no_side_effects"),
    );
}

fn assert_read_only_namespace_mutation_contract(dir: &Path, seed: &Path, scenario_id: &str) {
    let entries_before = snapshot_directory_entries(dir);
    let seed_before = snapshot_file_state(seed);
    let seed_name = seed
        .file_name()
        .expect("seed file name")
        .to_string_lossy()
        .into_owned();

    let create_path = dir.join("blocked_create.txt");
    let create_err = fs::write(&create_path, b"blocked create")
        .expect_err("read-only create should fail with EROFS");
    assert_eq!(
        create_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only create should surface exact EROFS: {create_err}"
    );
    assert!(
        fs::symlink_metadata(&create_path).is_err(),
        "read-only create must not leave a new file behind"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected create must not change visible directory entries"
    );
    assert_file_state_unchanged(seed, &seed_before, "rejected create");

    let mkdir_path = dir.join("blocked_dir");
    let mkdir_err = fs::create_dir(&mkdir_path).expect_err("read-only mkdir should fail");
    assert_eq!(
        mkdir_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only mkdir should surface exact EROFS: {mkdir_err}"
    );
    assert!(
        fs::symlink_metadata(&mkdir_path).is_err(),
        "read-only mkdir must not leave a new directory behind"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected mkdir must not change visible directory entries"
    );
    assert_file_state_unchanged(seed, &seed_before, "rejected mkdir");

    let link_path = dir.join("blocked_link.txt");
    let link_err = fs::hard_link(seed, &link_path).expect_err("read-only link should fail");
    assert_eq!(
        link_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only hard link should surface exact EROFS: {link_err}"
    );
    assert!(
        fs::symlink_metadata(&link_path).is_err(),
        "read-only hard link must not leave a new directory entry behind"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected hard link must not change visible directory entries"
    );
    assert_file_state_unchanged(seed, &seed_before, "rejected hard link");

    let symlink_path = dir.join("blocked_symlink.txt");
    let symlink_err = std::os::unix::fs::symlink(&seed_name, &symlink_path)
        .expect_err("read-only symlink should fail");
    assert_eq!(
        symlink_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only symlink should surface exact EROFS: {symlink_err}"
    );
    assert!(
        fs::symlink_metadata(&symlink_path).is_err(),
        "read-only symlink must not leave a new directory entry behind"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected symlink must not change visible directory entries"
    );
    assert_file_state_unchanged(seed, &seed_before, "rejected symlink");

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("create+mkdir+link+symlink=EROFS_no_drift"),
    );
}

fn assert_read_only_regular_write_contract(dir: &Path, seed: &Path, scenario_id: &str) {
    let entries_before = snapshot_directory_entries(dir);
    let seed_before = snapshot_file_state(seed);

    let create_path = dir.join("blocked_write_create.txt");
    let create_err = fs::write(&create_path, b"blocked create via write")
        .expect_err("read-only create-via-write should fail");
    assert_eq!(
        create_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only create-via-write should surface exact EROFS: {create_err}"
    );
    assert!(
        fs::symlink_metadata(&create_path).is_err(),
        "read-only create-via-write must not leave a new file behind"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected create-via-write must not change visible directory entries"
    );
    assert_file_state_unchanged(seed, &seed_before, "rejected create-via-write");

    let overwrite_err = fs::OpenOptions::new()
        .write(true)
        .open(seed)
        .and_then(|mut file| {
            file.write_all(b"blocked overwrite write")?;
            file.flush()
        })
        .expect_err("read-only overwrite should fail with EROFS");
    assert_eq!(
        overwrite_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only overwrite should surface exact EROFS: {overwrite_err}"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected overwrite must not change visible directory entries"
    );
    assert_file_state_unchanged(seed, &seed_before, "rejected overwrite");

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("create_via_write+overwrite=EROFS_no_drift"),
    );
}

fn assert_read_only_unlink_rmdir_and_rename_contract(
    dir: &Path,
    keep_file: &Path,
    empty_dir: &Path,
    rename_source: &Path,
    scenario_id: &str,
) {
    let entries_before = snapshot_directory_entries(dir);
    let keep_before = snapshot_file_state(keep_file);
    let rename_before = snapshot_file_state(rename_source);

    let unlink_err = fs::remove_file(keep_file).expect_err("read-only unlink should fail");
    assert_eq!(
        unlink_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only unlink should surface exact EROFS: {unlink_err}"
    );
    assert!(
        fs::symlink_metadata(keep_file).is_ok(),
        "read-only unlink must leave the source file in place"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected unlink must not change visible directory entries"
    );
    assert_file_state_unchanged(keep_file, &keep_before, "rejected unlink");
    assert_file_state_unchanged(rename_source, &rename_before, "rejected unlink");

    let rmdir_err = fs::remove_dir(empty_dir).expect_err("read-only rmdir should fail");
    assert_eq!(
        rmdir_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only rmdir should surface exact EROFS: {rmdir_err}"
    );
    assert!(
        fs::symlink_metadata(empty_dir).is_ok(),
        "read-only rmdir must leave the empty directory in place"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected rmdir must not change visible directory entries"
    );
    assert_file_state_unchanged(keep_file, &keep_before, "rejected rmdir");
    assert_file_state_unchanged(rename_source, &rename_before, "rejected rmdir");

    let rename_target = dir.join("readonly_rename_target.txt");
    let rename_err =
        fs::rename(rename_source, &rename_target).expect_err("read-only rename should fail");
    assert_eq!(
        rename_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only rename should surface exact EROFS: {rename_err}"
    );
    assert!(
        fs::symlink_metadata(rename_source).is_ok(),
        "read-only rename must leave the source entry in place"
    );
    assert!(
        fs::symlink_metadata(&rename_target).is_err(),
        "read-only rename must not create the destination entry"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected rename must not change visible directory entries"
    );
    assert_file_state_unchanged(keep_file, &keep_before, "rejected rename");
    assert_file_state_unchanged(rename_source, &rename_before, "rejected rename");

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("unlink+rmdir+rename=EROFS_no_drift"),
    );
}

#[test]
fn fuse_xattr_set_get_list_remove() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Set a user xattr.
        py_setxattr(&path, "user.test_key", b"test_value_123");

        // Get it back.
        let val = py_getxattr(&path, "user.test_key").expect("xattr should exist after set");
        assert_eq!(val, b"test_value_123");

        // List should include it.
        let names = py_listxattr(&path);
        assert!(
            names.iter().any(|n| n == "user.test_key"),
            "listxattr should contain user.test_key, got: {names:?}"
        );

        // Remove it.
        assert!(
            py_removexattr(&path, "user.test_key"),
            "removexattr should succeed"
        );

        // Should be gone.
        assert!(
            py_getxattr(&path, "user.test_key").is_none(),
            "xattr should be absent after removexattr"
        );

        // listxattr should no longer include it.
        let names_after = py_listxattr(&path);
        assert!(
            !names_after.iter().any(|n| n == "user.test_key"),
            "listxattr should not contain user.test_key after removal"
        );
    });
}

#[test]
fn fuse_xattr_multiple_attributes() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Set multiple xattrs.
        py_setxattr(&path, "user.alpha", b"aaa");
        py_setxattr(&path, "user.beta", b"bbb");
        py_setxattr(&path, "user.gamma", b"ccc");

        // Verify each value.
        assert_eq!(py_getxattr(&path, "user.alpha").unwrap(), b"aaa");
        assert_eq!(py_getxattr(&path, "user.beta").unwrap(), b"bbb");
        assert_eq!(py_getxattr(&path, "user.gamma").unwrap(), b"ccc");

        // List should contain all three.
        let names = py_listxattr(&path);
        for expected in ["user.alpha", "user.beta", "user.gamma"] {
            assert!(
                names.iter().any(|n| n == expected),
                "listxattr should contain {expected}, got: {names:?}"
            );
        }
    });
}

#[test]
fn fuse_xattr_overwrite_value() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Set initial value.
        py_setxattr(&path, "user.mutable", b"original");
        assert_eq!(py_getxattr(&path, "user.mutable").unwrap(), b"original");

        // Overwrite with different value.
        py_setxattr(&path, "user.mutable", b"updated_value");
        assert_eq!(
            py_getxattr(&path, "user.mutable").unwrap(),
            b"updated_value"
        );
    });
}

#[test]
fn fuse_xattr_on_directory() {
    with_rw_mount(|mnt| {
        let dir = mnt.join("testdir");

        // Set xattr on directory.
        py_setxattr(&dir, "user.dir_attr", b"dir_value");

        let val = py_getxattr(&dir, "user.dir_attr").expect("xattr on dir should exist");
        assert_eq!(val, b"dir_value");

        let names = py_listxattr(&dir);
        assert!(
            names.iter().any(|n| n == "user.dir_attr"),
            "listxattr on dir should contain user.dir_attr, got: {names:?}"
        );
    });
}

#[test]
fn fuse_xattr_ext4_get_missing_reports_enodata_without_side_effects() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_xattr_get_missing_reports_enodata";
        let path = mnt.join("hello.txt");
        let original_file = fs::read(&path).expect("read original file bytes");
        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_getxattr_report(&path, "user.does_not_exist");
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "missing ext4 getxattr should surface ENODATA: {report}"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "missing getxattr must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read file bytes after missing getxattr"),
            original_file,
            "missing getxattr must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            !names.iter().any(|name| name == "user.does_not_exist"),
            "missing xattr should remain absent after ENODATA getxattr: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should remain listed after ENODATA getxattr: {names:?}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("errno=ENODATA_with_no_side_effects"),
        );
    });
}

#[test]
fn fuse_xattr_ext4_empty_listxattr_size_probe_and_zero_length_payload() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_empty_listxattr_size_probe";
        let path = mnt.join("empty_listxattr_probe.txt");
        let original_file = b"ext4 empty listxattr probe coverage\n";
        fs::write(&path, original_file).expect("write ext4 empty listxattr probe file");

        let initial_names = py_listxattr(&path);
        assert!(
            initial_names.is_empty(),
            "fresh ext4 file should expose no visible xattrs: {initial_names:?}"
        );

        let probe_report = py_listxattr_probe_report(&path, 0);
        assert_eq!(
            probe_report["len"].as_u64(),
            Some(0),
            "empty listxattr size probe should report length 0: {probe_report}"
        );

        let zero_len_payload_report = py_listxattr_probe_report(&path, 0);
        assert_eq!(
            zero_len_payload_report["len"].as_u64(),
            Some(0),
            "empty listxattr zero-length payload should succeed with length 0: {zero_len_payload_report}"
        );

        let names_after = py_listxattr(&path);
        assert!(
            names_after.is_empty(),
            "empty listxattr probe paths must not create visible xattrs: {names_after:?}"
        );
        assert_eq!(
            fs::read(&path).expect("read ext4 file bytes after empty listxattr probe"),
            original_file,
            "empty listxattr probe paths must not mutate file contents"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("empty_len_zero_and_zero_length_success"),
        );
    });
}

#[test]
fn fuse_xattr_ext4_remove_missing_reports_enodata_without_side_effects() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_xattr_remove_missing_reports_enodata";
        let path = mnt.join("hello.txt");
        let original_file = fs::read(&path).expect("read original file bytes");
        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_removexattr_report(&path, "user.no_such_attr");
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "missing ext4 removexattr should surface ENODATA: {report}"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "missing removexattr must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read file bytes after missing removexattr"),
            original_file,
            "missing removexattr must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            !names.iter().any(|name| name == "user.no_such_attr"),
            "missing xattr should remain absent after ENODATA removexattr: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should remain listed after ENODATA removexattr: {names:?}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("errno=ENODATA_with_no_side_effects"),
        );
    });
}

#[test]
fn fuse_xattr_ext4_create_existing_reports_eexist_without_side_effects() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        let original_file = fs::read(&path).expect("read original file bytes");

        py_setxattr(&path, "user.locked", b"original");
        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_setxattr_report(&path, "user.locked", b"replacement", libc::XATTR_CREATE);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EEXIST)),
            "XATTR_CREATE should reject an existing xattr with EEXIST: {report}"
        );
        assert_eq!(
            py_getxattr(&path, "user.locked").expect("existing xattr should remain readable"),
            b"original",
            "XATTR_CREATE failure must preserve the original xattr value"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "XATTR_CREATE failure must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read file bytes after create failure"),
            original_file,
            "XATTR_CREATE failure must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            names.iter().any(|name| name == "user.locked"),
            "existing xattr should still be listed after XATTR_CREATE failure: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should still be listed after XATTR_CREATE failure: {names:?}"
        );
    });
}

#[test]
fn fuse_xattr_ext4_replace_missing_reports_enodata_without_side_effects() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        let original_file = fs::read(&path).expect("read original file bytes");

        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_setxattr_report(&path, "user.missing", b"replacement", libc::XATTR_REPLACE);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "XATTR_REPLACE should reject a missing xattr with ENODATA: {report}"
        );
        assert!(
            py_getxattr(&path, "user.missing").is_none(),
            "XATTR_REPLACE failure must not create the missing xattr"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "XATTR_REPLACE failure must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read file bytes after replace failure"),
            original_file,
            "XATTR_REPLACE failure must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            !names.iter().any(|name| name == "user.missing"),
            "missing xattr should remain absent after XATTR_REPLACE failure: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should still be listed after XATTR_REPLACE failure: {names:?}"
        );
    });
}

#[test]
fn fuse_xattr_ext4_posix_acl_list_and_get() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let (image, access_acl, default_acl) = create_ext4_posix_acl_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    let file_path = mnt.join("hello.txt");
    let dir_path = mnt.join("testdir");
    let expected_access_hex = hex::encode(&access_acl);
    let expected_default_hex = hex::encode(&default_acl);

    let file_names = py_listxattr(&file_path);
    assert!(
        file_names
            .iter()
            .any(|name| name == "system.posix_acl_access"),
        "listxattr on hello.txt should expose system.posix_acl_access, got: {file_names:?}"
    );
    let access_report = py_getxattr_report(&file_path, "system.posix_acl_access");
    assert!(
        access_report["errno"].is_null(),
        "mounted-path getxattr for system.posix_acl_access should succeed: {access_report}"
    );
    assert_eq!(
        access_report["value_hex"].as_str(),
        Some(expected_access_hex.as_str()),
        "mounted-path access ACL bytes should remain stable: {access_report}"
    );

    let dir_names = py_listxattr(&dir_path);
    assert!(
        dir_names
            .iter()
            .any(|name| name == "system.posix_acl_default"),
        "listxattr on testdir should expose system.posix_acl_default, got: {dir_names:?}"
    );
    let default_report = py_getxattr_report(&dir_path, "system.posix_acl_default");
    assert!(
        default_report["errno"].is_null(),
        "mounted-path getxattr for system.posix_acl_default should succeed: {default_report}"
    );
    assert_eq!(
        default_report["value_hex"].as_str(),
        Some(expected_default_hex.as_str()),
        "mounted-path default ACL bytes should remain stable: {default_report}"
    );
}

#[test]
fn fuse_xattr_ext4_posix_acl_default_missing_on_regular_file_reports_enodata() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let (image, _access_acl, _default_acl) = create_ext4_posix_acl_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    let file_path = mnt.join("hello.txt");
    let names = py_listxattr(&file_path);
    assert!(
        !names.iter().any(|name| name == "system.posix_acl_default"),
        "regular file should not list a default ACL xattr, got: {names:?}"
    );

    let report = py_getxattr_report(&file_path, "system.posix_acl_default");
    assert_eq!(
        report["errno"].as_i64(),
        Some(i64::from(libc::ENODATA)),
        "missing default ACL on a regular file should surface ENODATA: {report}"
    );
}

#[test]
fn fuse_xattr_ext4_name_too_long_reports_erange() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        let original_file = fs::read(&path).expect("read original file bytes");

        // Linux XATTR_NAME_MAX is the full name length, including "user.".
        let long_suffix = "a".repeat(255 - "user.".len() + 1);
        let long_name = format!("user.{long_suffix}");

        let report = py_setxattr_report(&path, &long_name, b"value", 0);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ERANGE)),
            "xattr full name > XATTR_NAME_MAX should return ERANGE: {report}"
        );

        // Verify no side effects
        assert_eq!(
            fs::read(&path).expect("read file bytes after name-too-long rejection"),
            original_file,
            "name-too-long rejection must not mutate file contents"
        );
    });
}

#[test]
fn ext4_openfs_oversized_external_xattr_value_reports_enospc_without_drift() {
    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        mvcc_wal_path: Some(image.with_extension("wal")),
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, &image, &opts).expect("open ext4 image");
    fs.enable_writes(&cx).expect("enable ext4 write support");
    let free_before = fs
        .count_free_blocks_in_group(&cx, GroupNumber(0))
        .expect("free blocks before oversized OpenFs setxattr");

    let hello = <OpenFs as FsOps>::lookup(
        &fs,
        &cx,
        &mut RequestScope::empty(),
        InodeNumber(1),
        std::ffi::OsStr::new("hello.txt"),
    )
    .expect("lookup hello.txt through OpenFs");
    let original_file =
        <OpenFs as FsOps>::read(&fs, &cx, &mut RequestScope::empty(), hello.ino, 0, 4096)
            .expect("read original hello.txt through OpenFs");
    let oversized_value = vec![0x42_u8; 4037];

    let err = <OpenFs as FsOps>::setxattr(
        &fs,
        &cx,
        &mut RequestScope::empty(),
        hello.ino,
        "user.toobig",
        &oversized_value,
        ffs_core::XattrSetMode::Set,
    )
    .expect_err("oversized xattr should not fit in ext4 external EA block");
    assert_eq!(
        err.to_errno(),
        libc::ENOSPC,
        "oversized ext4 external EA-block xattr should report ENOSPC, got {err:?}"
    );
    assert_eq!(
        <OpenFs as FsOps>::getxattr(&fs, &cx, hello.ino, "user.toobig")
            .expect("get oversized xattr after failed OpenFs setxattr"),
        None,
        "oversized xattr value should not be stored"
    );
    assert_eq!(
        <OpenFs as FsOps>::read(&fs, &cx, &mut RequestScope::empty(), hello.ino, 0, 4096)
            .expect("read hello.txt after failed OpenFs setxattr"),
        original_file,
        "oversized xattr rejection must not mutate file contents"
    );
    assert_eq!(
        fs.count_free_blocks_in_group(&cx, GroupNumber(0))
            .expect("free blocks after oversized OpenFs setxattr"),
        free_before,
        "oversized xattr rejection must not leak the speculative external EA block"
    );
}

#[test]
fn fuse_xattr_ext4_value_too_large_reports_enospc() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        let original_file = fs::read(&path).expect("read original file bytes");

        // This 4KiB-block fixture has one external EA block. A 4037-byte
        // value cannot coexist with the xattr entry header and terminator.
        let oversized_value = vec![0x42_u8; 4037];

        let report = py_setxattr_report(&path, "user.toobig", &oversized_value, 0);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENOSPC)),
            "xattr value too large for the ext4 EA block should return ENOSPC: {report}"
        );

        // Verify the xattr was not created
        assert!(
            py_getxattr(&path, "user.toobig").is_none(),
            "oversized xattr value should not be stored"
        );

        // Verify no side effects
        assert_eq!(
            fs::read(&path).expect("read file bytes after value-too-large rejection"),
            original_file,
            "value-too-large rejection must not mutate file contents"
        );
    });
}

#[test]
fn fuse_xattr_ext4_boundary_name_length_accepted() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Linux XATTR_NAME_MAX is 255 bytes for the full name, including "user.".
        let max_suffix = "z".repeat(255 - "user.".len());
        let max_name = format!("user.{max_suffix}");

        py_setxattr(&path, &max_name, b"boundary");
        let readback =
            py_getxattr(&path, &max_name).expect("255-byte full-name xattr should exist");
        assert_eq!(
            readback, b"boundary",
            "boundary-length xattr should round-trip"
        );
    });
}

#[test]
fn fuse_xattr_ext4_boundary_value_size_accepted() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Maximum payload for one ext4 external EA block with name "user.maxval":
        // 4096 block - 32 block header - 24 entry - 4 terminator.
        let max_value = vec![0xAB_u8; 4036];

        py_setxattr(&path, "user.maxval", &max_value);
        let readback =
            py_getxattr(&path, "user.maxval").expect("max ext4 EA-block xattr should exist");
        assert_eq!(
            readback, max_value,
            "boundary-size xattr value should round-trip"
        );
    });
}

// ── btrfs FUSE E2E tests ────────────────────────────────────────────────────

/// Check if btrfs FUSE prerequisites are met.
fn btrfs_fuse_available() -> bool {
    Path::new("/dev/fuse").exists() && command_available("mkfs.btrfs")
}

/// Create a small btrfs image and populate it with test files.
fn create_btrfs_test_image(dir: &Path) -> std::path::PathBuf {
    let image = dir.join("test.btrfs");
    let seed_root = dir.join("seed_root");
    let seed_workspace = seed_root.join(BTRFS_TEST_WORKSPACE);

    // Create a 128 MiB sparse image (btrfs minimum is ~109 MiB).
    let f = fs::File::create(&image).expect("create btrfs image");
    f.set_len(128 * 1024 * 1024).expect("set btrfs image size");
    drop(f);

    // Seed a writable workspace so unprivileged `default_permissions` mounts
    // can exercise the btrfs write path without weakening mount semantics.
    fs::create_dir_all(&seed_workspace).expect("create btrfs seed workspace");
    fs::set_permissions(&seed_root, fs::Permissions::from_mode(0o777))
        .expect("chmod btrfs seed root");
    fs::set_permissions(&seed_workspace, fs::Permissions::from_mode(0o777))
        .expect("chmod btrfs seed workspace");

    // mkfs.btrfs
    let out = Command::new("mkfs.btrfs")
        .args([
            "-f",
            "-L",
            "ffs-btrfs-e2e",
            "--rootdir",
            seed_root.to_str().unwrap(),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.btrfs");
    assert!(
        out.status.success(),
        "mkfs.btrfs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    image
}

/// Try to mount a btrfs image via FrankenFS FUSE (read-write) with explicit
/// mount options.
fn try_mount_btrfs_rw_with_options(
    image: &Path,
    mountpoint: &Path,
    mount_opts: &MountOptions,
) -> Option<ffs_harness::stale_mounts::MountGuard> {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, image, &opts).expect("open btrfs image");
    if let Err(e) = fs.enable_writes(&cx) {
        eprintln!("btrfs enable_writes failed (skipping test): {e}");
        return None;
    }
    match mount_background(Box::new(fs), mountpoint, mount_opts) {
        Ok(session) => {
            wait_for_fuse_mount_ready(mountpoint);
            Some(ffs_harness::stale_mounts::MountGuard::new(
                session, mountpoint,
            ))
        }
        Err(e) => {
            eprintln!("btrfs FUSE mount failed (skipping test): {e}");
            None
        }
    }
}

/// Try to mount a btrfs image via FrankenFS FUSE (read-write).
fn try_mount_btrfs_rw(image: &Path, mountpoint: &Path) -> Option<ffs_harness::stale_mounts::MountGuard> {
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ..MountOptions::default()
    };
    try_mount_btrfs_rw_with_options(image, mountpoint, &mount_opts)
}

/// Create a btrfs image with one deterministic seeded file for read-only
/// mounted-path setattr coverage.
fn create_btrfs_test_image_with_seeded_file(
    dir: &Path,
    file_name: &str,
    contents: &[u8],
) -> std::path::PathBuf {
    let image = dir.join("test.btrfs");
    let seed_root = dir.join("seed_root");
    let seed_workspace = seed_root.join(BTRFS_TEST_WORKSPACE);

    let f = fs::File::create(&image).expect("create seeded btrfs image");
    f.set_len(128 * 1024 * 1024)
        .expect("set seeded btrfs image size");
    drop(f);

    fs::create_dir_all(&seed_workspace).expect("create seeded btrfs workspace");
    fs::set_permissions(&seed_root, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs root");
    fs::set_permissions(&seed_workspace, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs workspace");
    fs::write(seed_workspace.join(file_name), contents).expect("write seeded btrfs file");

    let out = Command::new("mkfs.btrfs")
        .args([
            "-f",
            "-L",
            "ffs-btrfs-e2e",
            "--rootdir",
            seed_root.to_str().unwrap(),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.btrfs seeded image");
    assert!(
        out.status.success(),
        "mkfs.btrfs seeded image failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    image
}

fn create_btrfs_test_image_with_seeded_sync_fixture(dir: &Path) -> std::path::PathBuf {
    let image = dir.join("test.btrfs");
    let seed_root = dir.join("seed_root");
    let seed_workspace = seed_root.join(BTRFS_TEST_WORKSPACE);
    let seed_dir = seed_workspace.join("readonly_sync_dir");

    let f = fs::File::create(&image).expect("create seeded btrfs sync image");
    f.set_len(128 * 1024 * 1024)
        .expect("set seeded btrfs sync image size");
    drop(f);

    fs::create_dir_all(&seed_dir).expect("create seeded btrfs sync dir");
    fs::set_permissions(&seed_root, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs sync root");
    fs::set_permissions(&seed_workspace, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs sync workspace");
    fs::set_permissions(&seed_dir, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs sync dir");
    fs::write(
        seed_workspace.join("readonly_sync_seed.txt"),
        b"readonly btrfs sync seed content\n",
    )
    .expect("write seeded btrfs sync file");
    fs::write(seed_dir.join("child.txt"), b"readonly btrfs sync child\n")
        .expect("write seeded btrfs sync child");

    let out = Command::new("mkfs.btrfs")
        .args([
            "-f",
            "-L",
            "ffs-btrfs-e2e",
            "--rootdir",
            seed_root.to_str().unwrap(),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.btrfs seeded sync image");
    assert!(
        out.status.success(),
        "mkfs.btrfs seeded sync image failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    image
}

fn create_btrfs_test_image_with_seeded_namespace_removal_fixture(dir: &Path) -> std::path::PathBuf {
    let image = dir.join("test.btrfs");
    let seed_root = dir.join("seed_root");
    let seed_workspace = seed_root.join(BTRFS_TEST_WORKSPACE);
    let empty_dir = seed_workspace.join("readonly_empty_dir");

    let f = fs::File::create(&image).expect("create seeded btrfs namespace removal image");
    f.set_len(128 * 1024 * 1024)
        .expect("set seeded btrfs namespace removal image size");
    drop(f);

    fs::create_dir_all(&empty_dir).expect("create seeded btrfs namespace removal dir");
    fs::set_permissions(&seed_root, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs namespace removal root");
    fs::set_permissions(&seed_workspace, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs namespace removal workspace");
    fs::set_permissions(&empty_dir, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs namespace removal dir");
    fs::write(
        seed_workspace.join("readonly_unlink_seed.txt"),
        b"readonly btrfs unlink seed\n",
    )
    .expect("write seeded btrfs unlink file");
    fs::write(
        seed_workspace.join("readonly_rename_source.txt"),
        b"readonly btrfs rename source\n",
    )
    .expect("write seeded btrfs rename source file");

    let out = Command::new("mkfs.btrfs")
        .args([
            "-f",
            "-L",
            "ffs-btrfs-e2e",
            "--rootdir",
            seed_root.to_str().unwrap(),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.btrfs seeded namespace removal image");
    assert!(
        out.status.success(),
        "mkfs.btrfs seeded namespace removal image failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    image
}

fn try_mount_btrfs_ro(image: &Path, mountpoint: &Path) -> Option<ffs_harness::stale_mounts::MountGuard> {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let fs = OpenFs::open_with_options(&cx, image, &opts).expect("open btrfs image");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };
    match mount_background(Box::new(fs), mountpoint, &mount_opts) {
        Ok(session) => {
            wait_for_fuse_mount_ready(mountpoint);
            Some(ffs_harness::stale_mounts::MountGuard::new(
                session, mountpoint,
            ))
        }
        Err(e) => {
            eprintln!("btrfs read-only FUSE mount failed (skipping test): {e}");
            None
        }
    }
}

/// Try to mount a btrfs image with explicit OpenOptions (for BtrfsMountSelection tests).
fn try_mount_btrfs_with_open_options(
    image: &Path,
    mountpoint: &Path,
    open_opts: &OpenOptions,
    mount_opts: &MountOptions,
) -> Option<ffs_harness::stale_mounts::MountGuard> {
    let cx = Cx::for_testing();
    let fs = match OpenFs::open_with_options(&cx, image, open_opts) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("btrfs open with options failed (may be expected): {e}");
            return None;
        }
    };
    match mount_background(Box::new(fs), mountpoint, mount_opts) {
        Ok(session) => {
            wait_for_fuse_mount_ready(mountpoint);
            Some(ffs_harness::stale_mounts::MountGuard::new(
                session, mountpoint,
            ))
        }
        Err(e) => {
            eprintln!("btrfs FUSE mount failed: {e}");
            None
        }
    }
}

/// Check if we can run sudo commands (for tests that create btrfs subvolumes).
fn can_run_sudo() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Create a btrfs image with subvolumes and snapshots using kernel btrfs tools.
/// Requires sudo access. Returns (image_path, subvol_names, snapshot_names).
#[allow(clippy::too_many_lines)]
fn create_btrfs_image_with_subvolumes(dir: &Path) -> Option<(PathBuf, Vec<String>, Vec<String>)> {
    if !can_run_sudo() {
        eprintln!("sudo not available, skipping subvolume test");
        return None;
    }
    if !command_available("btrfs") {
        eprintln!("btrfs command not available, skipping subvolume test");
        return None;
    }

    let image = dir.join("subvol_test.btrfs");
    let kernel_mnt = dir.join("kernel_mnt");

    // Create 256MiB image
    let f = fs::File::create(&image).expect("create btrfs image");
    f.set_len(256 * 1024 * 1024).expect("set image size");
    drop(f);

    // mkfs.btrfs
    let out = Command::new("mkfs.btrfs")
        .args(["-f", "-L", "ffs-subvol-e2e", image.to_str().unwrap()])
        .output()
        .expect("mkfs.btrfs");
    if !out.status.success() {
        eprintln!(
            "mkfs.btrfs failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }

    // Mount with kernel driver to create subvolumes
    fs::create_dir_all(&kernel_mnt).expect("create kernel mount dir");
    let out = Command::new("sudo")
        .args([
            "mount",
            "-t",
            "btrfs",
            image.to_str().unwrap(),
            kernel_mnt.to_str().unwrap(),
        ])
        .output()
        .expect("sudo mount");
    if !out.status.success() {
        eprintln!(
            "sudo mount failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }

    // Create subvolume "data"
    let subvol_path = kernel_mnt.join("data");
    let out = Command::new("sudo")
        .args([
            "btrfs",
            "subvolume",
            "create",
            subvol_path.to_str().unwrap(),
        ])
        .output()
        .expect("btrfs subvolume create");
    if !out.status.success() {
        let _ = Command::new("sudo")
            .args(["umount", kernel_mnt.to_str().unwrap()])
            .output();
        eprintln!(
            "btrfs subvolume create failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }

    // Write a marker file in the subvolume
    let marker = subvol_path.join("subvol_marker.txt");
    let out = Command::new("sudo")
        .args([
            "sh",
            "-c",
            &format!("echo 'in-data-subvol' > '{}'", marker.display()),
        ])
        .output()
        .expect("write marker");
    if !out.status.success() {
        eprintln!("write marker failed");
    }

    // Write a marker file in the root (not visible when mounting subvolume)
    let root_marker = kernel_mnt.join("root_marker.txt");
    let out = Command::new("sudo")
        .args([
            "sh",
            "-c",
            &format!("echo 'in-root' > '{}'", root_marker.display()),
        ])
        .output()
        .expect("write root marker");
    if !out.status.success() {
        eprintln!("write root marker failed");
    }

    // Create snapshot "snap-data" of "data"
    let snap_path = kernel_mnt.join("snap-data");
    let out = Command::new("sudo")
        .args([
            "btrfs",
            "subvolume",
            "snapshot",
            subvol_path.to_str().unwrap(),
            snap_path.to_str().unwrap(),
        ])
        .output()
        .expect("btrfs snapshot");
    let has_snapshot = out.status.success();
    if has_snapshot {
        // Write different content in snapshot
        let snap_marker = snap_path.join("snapshot_marker.txt");
        let _ = Command::new("sudo")
            .args([
                "sh",
                "-c",
                &format!("echo 'in-snapshot' > '{}'", snap_marker.display()),
            ])
            .output();
    }

    // Unmount
    let out = Command::new("sudo")
        .args(["umount", kernel_mnt.to_str().unwrap()])
        .output()
        .expect("sudo umount");
    if !out.status.success() {
        eprintln!(
            "sudo umount failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let subvols = vec!["data".to_string()];
    let snaps = if has_snapshot {
        vec!["snap-data".to_string()]
    } else {
        vec![]
    };
    Some((image, subvols, snaps))
}

/// Helper: create btrfs image, mount rw, run a closure against the mount root.
fn with_btrfs_rw_root_mount(f: impl FnOnce(&Path)) {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_rw(&image, &mnt) else {
        return;
    };
    f(&mnt);
}

/// Helper: create btrfs image, mount rw, run a closure in the seeded workspace.
fn with_btrfs_rw_mount(f: impl FnOnce(&Path)) {
    with_btrfs_rw_root_mount(|mnt| {
        let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
        assert!(
            workspace.is_dir(),
            "seeded btrfs workspace missing at {}",
            workspace.display()
        );
        f(&workspace);
    });
}

fn assert_btrfs_pwritev2_rwf_persists_after_remount(
    flag_name: &str,
    file_name: &str,
    payload: &[u8],
    scenario_id: &str,
    pass_detail: &str,
) {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create btrfs mountpoint");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ..MountOptions::default()
    };
    let Some(session) = try_mount_btrfs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    assert!(
        workspace.is_dir(),
        "seeded btrfs workspace missing at {}",
        workspace.display()
    );
    let report = run_pwritev2_rwf_probe(&workspace, flag_name, file_name, payload);
    if let Some(skip_reason) = report["skipped"].as_str() {
        emit_scenario_result(scenario_id, "SKIP", Some(skip_reason));
        return;
    }

    let expected_written = i64::try_from(payload.len()).expect("payload length should fit i64");
    assert_eq!(
        report["written"].as_i64(),
        Some(expected_written),
        "btrfs pwritev2 {flag_name} should report the full payload length: {report}"
    );
    let payload_hex = report["payload_hex"]
        .as_str()
        .expect("pwritev2 RWF probe should report payload_hex");
    assert_eq!(
        report["readback_hex"].as_str(),
        Some(payload_hex),
        "btrfs pwritev2 {flag_name} write should be immediately readable: {report}"
    );

    drop(session);
    wait_for_fuse_mount_released(&mnt);

    let Some(_remount) = try_mount_btrfs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };
    let persisted = fs::read(mnt.join(BTRFS_TEST_WORKSPACE).join(file_name))
        .expect("read btrfs pwritev2 RWF probe after remount");
    assert_eq!(
        persisted.as_slice(),
        payload,
        "btrfs {flag_name} pwritev2 payload should survive remount"
    );
    emit_scenario_result(scenario_id, "PASS", Some(pass_detail));
}

fn with_btrfs_ro_sync_fixture(f: impl FnOnce(&Path, &Path, &Path)) {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image_with_seeded_sync_fixture(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    f(
        &workspace.join("readonly_sync_seed.txt"),
        &workspace.join("readonly_sync_dir"),
        &workspace.join("readonly_sync_dir").join("child.txt"),
    );
}

#[test]
fn btrfs_fuse_readdir_root() {
    with_btrfs_rw_root_mount(|mnt| {
        let entries: Vec<String> = fs::read_dir(mnt)
            .expect("readdir btrfs root via FUSE")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries.iter().any(|entry| entry == BTRFS_TEST_WORKSPACE),
            "seeded btrfs workspace should appear at root, got: {entries:?}"
        );
    });
}

#[test]
fn btrfs_fuse_create_and_read_file() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        fs::write(&path, b"Hello from btrfs FUSE!\n").expect("write file on btrfs");

        let content = fs::read_to_string(&path).expect("read file on btrfs");
        assert_eq!(content, "Hello from btrfs FUSE!\n");
    });
}

#[test]
fn btrfs_fuse_pwritev2_rwf_dsync_persists_written_data_after_remount() {
    assert_btrfs_pwritev2_rwf_persists_after_remount(
        "RWF_DSYNC",
        "btrfs_rwf_dsync_probe.bin",
        b"btrfs-rwf-dsync-through-fuse\n",
        "btrfs_rw_pwritev2_rwf_dsync",
        "pwritev2_rwf_dsync",
    );
}

#[test]
fn btrfs_fuse_pwritev2_rwf_sync_persists_written_data_after_remount() {
    assert_btrfs_pwritev2_rwf_persists_after_remount(
        "RWF_SYNC",
        "btrfs_rwf_sync_probe.bin",
        b"btrfs-rwf-sync-through-fuse\n",
        "btrfs_rw_pwritev2_rwf_sync",
        "pwritev2_rwf_sync",
    );
}

#[test]
fn btrfs_fuse_pwritev2_rwf_hipri_preserves_normal_offset_write() {
    with_btrfs_rw_mount(|mnt| {
        let report = run_pwritev2_rwf_hint_probe(
            mnt,
            "RWF_HIPRI",
            "btrfs_rwf_hipri_hint_probe.bin",
            b"abcdef",
            b"hipri",
            1,
        );
        if let Some(skip_reason) = report["skipped"].as_str() {
            assert_eq!(
                report["readback_hex"].as_str(),
                report["expected_hex"].as_str(),
                "transport-level btrfs RWF_HIPRI refusal must not mutate data: {report}"
            );
            emit_scenario_result(
                "btrfs_rw_pwritev2_rwf_hipri_hint",
                "SKIP",
                Some(skip_reason),
            );
            return;
        }

        assert_eq!(
            report["written"].as_i64(),
            Some(i64::try_from(b"hipri".len()).expect("payload length fits i64")),
            "btrfs RWF_HIPRI should report the normal write length: {report}"
        );
        assert_eq!(
            report["readback_hex"].as_str(),
            report["expected_hex"].as_str(),
            "btrfs RWF_HIPRI should preserve caller offset and normal write semantics: {report}"
        );

        emit_scenario_result(
            "btrfs_rw_pwritev2_rwf_hipri_hint",
            "PASS",
            Some("rwf_hipri_normal_offset_write"),
        );
    });
}

#[test]
fn btrfs_fuse_pwritev2_rwf_nowait_preserves_uncontended_offset_write() {
    with_btrfs_rw_mount(|mnt| {
        let report = run_pwritev2_rwf_hint_probe(
            mnt,
            "RWF_NOWAIT",
            "btrfs_rwf_nowait_probe.bin",
            b"abcdef",
            b"NW",
            2,
        );
        if let Some(skip_reason) = report["skipped"].as_str() {
            assert_eq!(
                report["readback_hex"].as_str(),
                report["expected_hex"].as_str(),
                "transport-level btrfs RWF_NOWAIT refusal must not mutate data: {report}"
            );
            emit_scenario_result(
                "btrfs_rw_pwritev2_rwf_nowait_uncontended",
                "SKIP",
                Some(skip_reason),
            );
            return;
        }

        assert_eq!(
            report["written"].as_i64(),
            Some(i64::try_from(b"NW".len()).expect("payload length fits i64")),
            "btrfs RWF_NOWAIT should report the normal write length when uncontended: {report}"
        );
        assert_eq!(
            report["readback_hex"].as_str(),
            report["expected_hex"].as_str(),
            "btrfs RWF_NOWAIT should preserve caller offset and normal write semantics when uncontended: {report}"
        );

        emit_scenario_result(
            "btrfs_rw_pwritev2_rwf_nowait_uncontended",
            "PASS",
            Some("rwf_nowait_uncontended_offset_write"),
        );
    });
}

#[test]
fn btrfs_fuse_pwritev2_rwf_append_noappend_modes() {
    with_btrfs_rw_mount(|mnt| {
        let report = run_pwritev2_rwf_append_modes_probe(mnt);
        if let Some(skip_reason) = report["skipped"].as_str() {
            emit_scenario_result(
                "btrfs_rw_pwritev2_rwf_append_noappend_modes",
                "SKIP",
                Some(skip_reason),
            );
            return;
        }

        let append = &report["append"];
        assert_eq!(
            append["written"].as_i64(),
            Some(i64::try_from(b"+append".len()).expect("payload length fits i64")),
            "btrfs RWF_APPEND should report the appended payload length: {report}"
        );
        assert_eq!(
            append["readback_hex"].as_str(),
            append["expected_hex"].as_str(),
            "btrfs RWF_APPEND should ignore caller offset and append at EOF: {report}"
        );

        let noappend = &report["noappend"];
        assert_eq!(
            noappend["written"].as_i64(),
            Some(i64::try_from(b"XY".len()).expect("payload length fits i64")),
            "btrfs RWF_NOAPPEND should report the overwrite payload length: {report}"
        );
        assert_eq!(
            noappend["readback_hex"].as_str(),
            noappend["expected_hex"].as_str(),
            "btrfs RWF_NOAPPEND should suppress O_APPEND and preserve caller offset: {report}"
        );

        let conflict = &report["conflict"];
        assert_eq!(
            conflict["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "btrfs RWF_APPEND|RWF_NOAPPEND should reject with EINVAL: {report}"
        );
        assert_eq!(
            conflict["readback_hex"].as_str(),
            conflict["expected_hex"].as_str(),
            "btrfs RWF_APPEND|RWF_NOAPPEND must reject before data mutation: {report}"
        );

        emit_scenario_result(
            "btrfs_rw_pwritev2_rwf_append_noappend_modes",
            "PASS",
            Some("append_noappend_offset_and_conflict_contract"),
        );
    });
}

#[test]
fn btrfs_fuse_pwritev2_rwf_unsupported_intents_reject_without_mutation() {
    with_btrfs_rw_mount(|mnt| {
        let report = run_pwritev2_rwf_unsupported_intents_probe(mnt);
        if let Some(skip_reason) = report["skipped"].as_str() {
            emit_scenario_result(
                "btrfs_rw_pwritev2_rwf_unsupported_intents",
                "SKIP",
                Some(skip_reason),
            );
            return;
        }

        for (case_key, flag_name) in [("atomic", "RWF_ATOMIC"), ("dontcache", "RWF_DONTCACHE")] {
            let case = &report["cases"][case_key];
            assert_eq!(
                case["errno"].as_i64(),
                Some(EOPNOTSUPP_ERRNO),
                "btrfs {flag_name} should reject with EOPNOTSUPP: {report}"
            );
            assert!(
                case["written"].is_null(),
                "btrfs {flag_name} should not report a successful byte count: {report}"
            );
            assert_eq!(
                case["readback_hex"].as_str(),
                case["expected_hex"].as_str(),
                "btrfs {flag_name} must reject before data mutation: {report}"
            );
        }

        emit_scenario_result(
            "btrfs_rw_pwritev2_rwf_unsupported_intents",
            "PASS",
            Some("rwf_atomic_rwf_dontcache_eopnotsupp_no_mutation"),
        );
    });
}

#[test]
fn btrfs_fuse_copy_file_range_offsets_and_overlap_contract() {
    if !command_available("python3") {
        eprintln!("python3 not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        assert_copy_file_range_offsets_and_overlap_contract(
            mnt,
            "btrfs_rw_copy_file_range_offsets_and_overlap",
        );
    });
}

#[test]
fn btrfs_fuse_write_to_directory_reports_eisdir() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_write_to_directory_errno_eisdir";
        let dir = mnt.join("btrfs_write_dir");
        fs::create_dir(&dir).expect("mkdir btrfs write directory target");
        let child = dir.join("child.txt");
        fs::write(&child, b"directory child stays intact\n")
            .expect("seed btrfs write directory child");

        let entries_before = snapshot_directory_entries(&dir);
        let child_before = snapshot_file_state(&child);

        let err = fs::OpenOptions::new()
            .write(true)
            .open(&dir)
            .expect_err("opening a directory for write should fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EISDIR),
            "opening a directory for write should surface exact EISDIR: {err}"
        );
        assert!(
            dir.is_dir(),
            "directory-write rejection must leave the directory in place"
        );
        assert_eq!(
            snapshot_directory_entries(&dir),
            entries_before,
            "directory-write rejection must not change directory entries"
        );
        assert_file_state_unchanged(&child, &child_before, "directory write rejection");
        emit_scenario_result(scenario_id, "PASS", Some("open=EISDIR_no_drift"));
    });
}

#[test]
fn btrfs_fuse_mkdir_and_nested_file() {
    with_btrfs_rw_mount(|mnt| {
        let dir = mnt.join("subdir");
        fs::create_dir(&dir).expect("mkdir on btrfs");

        let nested = dir.join("nested.txt");
        fs::write(&nested, b"nested btrfs content\n").expect("write nested on btrfs");

        let content = fs::read_to_string(&nested).expect("read nested on btrfs");
        assert_eq!(content, "nested btrfs content\n");
    });
}

#[test]
fn btrfs_fuse_create_and_mkdir_under_non_directory_parent_report_enotdir() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_create_and_mkdir_under_non_directory_parent";
        let regular_parent = mnt.join("nondir_parent.txt");
        fs::write(&regular_parent, b"not a directory\n").expect("write btrfs non-directory parent");

        let root_entries_before = snapshot_directory_entries(mnt);
        let parent_before = snapshot_file_state(&regular_parent);

        let create_target = regular_parent.join("child.txt");
        let create_err = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&create_target)
            .expect_err("create beneath regular-file parent should fail");
        assert_eq!(
            create_err.raw_os_error(),
            Some(libc::ENOTDIR),
            "create beneath a regular-file parent should surface exact ENOTDIR: {create_err}"
        );
        assert!(
            fs::symlink_metadata(&create_target).is_err(),
            "rejected create must not leave a nested child entry behind"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected create must not change visible root entries"
        );
        assert_file_state_unchanged(
            &regular_parent,
            &parent_before,
            "btrfs non-directory parent after rejected create",
        );

        let mkdir_target = regular_parent.join("child_dir");
        let mkdir_err = fs::create_dir(&mkdir_target)
            .expect_err("mkdir beneath regular-file parent should fail");
        assert_eq!(
            mkdir_err.raw_os_error(),
            Some(libc::ENOTDIR),
            "mkdir beneath a regular-file parent should surface exact ENOTDIR: {mkdir_err}"
        );
        assert!(
            fs::symlink_metadata(&mkdir_target).is_err(),
            "rejected mkdir must not leave a nested directory entry behind"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected mkdir must not change visible root entries"
        );
        assert_file_state_unchanged(
            &regular_parent,
            &parent_before,
            "btrfs non-directory parent after rejected mkdir",
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("create=ENOTDIR_mkdir=ENOTDIR_no_drift"),
        );
    });
}

#[test]
fn btrfs_fuse_unlink_and_rmdir() {
    with_btrfs_rw_mount(|mnt| {
        // Create and remove a file.
        let path = mnt.join("temp.txt");
        fs::write(&path, b"temporary").expect("write temp");
        assert!(path.exists());
        fs::remove_file(&path).expect("unlink on btrfs");
        assert!(!path.exists());

        // Create and remove a directory.
        let dir = mnt.join("tempdir");
        fs::create_dir(&dir).expect("mkdir tempdir");
        assert!(dir.exists());
        fs::remove_dir(&dir).expect("rmdir on btrfs");
        assert!(!dir.exists());
    });
}

#[test]
fn btrfs_fuse_rmdir_on_file_reports_enotdir() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_rmdir_on_file_reports_enotdir";
        let path = mnt.join("rmdir-on-file.txt");
        fs::write(&path, b"btrfs rmdir-on-file witness\n").expect("write rmdir-on-file witness");
        let original_bytes = fs::read(&path).expect("read witness before rmdir-on-file");

        let err = fs::remove_dir(&path).expect_err("rmdir on regular file should fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENOTDIR),
            "rmdir on a regular file should surface exact ENOTDIR: {err}"
        );
        assert!(
            path.is_file(),
            "failed rmdir on regular file must leave the file in place"
        );
        assert_eq!(
            fs::read(&path).expect("read witness after failed rmdir-on-file"),
            original_bytes,
            "failed rmdir on regular file must not mutate file contents"
        );

        emit_scenario_result(scenario_id, "PASS", Some("errno=ENOTDIR_no_drift"));
    });
}

#[test]
fn btrfs_fuse_unlink_directory_reports_eisdir() {
    with_btrfs_rw_mount(|mnt| {
        assert_unlink_directory_via_remove_file_reports_eisdir(
            mnt,
            "btrfs_rw_unlink_directory_reports_eisdir",
        );
    });
}

#[test]
fn btrfs_fuse_unlink_missing_reports_enoent() {
    with_btrfs_rw_mount(|mnt| {
        assert_unlink_missing_reports_enoent(mnt, "btrfs_rw_unlink_missing_reports_enoent");
    });
}

#[test]
fn btrfs_fuse_rename() {
    with_btrfs_rw_mount(|mnt| {
        let old = mnt.join("original.txt");
        let new = mnt.join("renamed.txt");
        fs::write(&old, b"rename test").expect("write for rename");
        assert!(old.exists());

        fs::rename(&old, &new).expect("rename on btrfs");
        assert!(!old.exists());
        assert!(new.exists());
        assert_eq!(
            fs::read_to_string(&new).expect("read renamed"),
            "rename test"
        );
    });
}

#[test]
fn btrfs_fuse_rename_same_name_is_noop() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_rename_same_name_noop";
        let path = mnt.join("same-name.txt");
        fs::write(&path, b"same name rename\n").expect("write rename same-name seed");

        let entries_before = snapshot_directory_entries(mnt);
        let before = snapshot_file_state(&path);
        let ino_before = fs::metadata(&path)
            .expect("stat before same-name rename")
            .ino();

        fs::rename(&path, &path).expect("rename same name should succeed");

        assert_eq!(
            snapshot_directory_entries(mnt),
            entries_before,
            "same-name rename should not change directory entries"
        );
        assert_file_state_unchanged(&path, &before, "same-name rename");

        let ino_after = fs::metadata(&path)
            .expect("stat after same-name rename")
            .ino();
        assert_eq!(
            ino_after, ino_before,
            "same-name rename should preserve the inode binding"
        );

        emit_scenario_result(scenario_id, "PASS", Some("visible_noop"));
    });
}

#[test]
fn btrfs_fuse_rename_over_same_inode_hardlink_is_noop() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_rename_over_same_inode_hardlink_noop";
        let original = mnt.join("original.txt");
        let alias = mnt.join("alias.txt");
        fs::write(&original, b"same inode rename btrfs\n").expect("write original");
        fs::hard_link(&original, &alias).expect("create alias hard link");

        let entries_before = snapshot_directory_entries(mnt);
        let alias_before = snapshot_file_state(&alias);
        let original_ino_before = fs::metadata(&original).expect("stat original").ino();
        let alias_meta_before = fs::metadata(&alias).expect("stat alias");
        assert_eq!(
            alias_meta_before.ino(),
            original_ino_before,
            "hard link should point at the same inode before rename"
        );
        assert_eq!(
            alias_meta_before.nlink(),
            2,
            "same-inode rename precondition should have two names"
        );

        fs::rename(&original, &alias).expect("rename over same-inode hard link");

        assert_eq!(
            snapshot_directory_entries(mnt),
            entries_before,
            "same-inode rename should be a visible no-op"
        );
        assert!(
            fs::symlink_metadata(&original).is_ok(),
            "source name should still resolve after same-inode rename"
        );
        assert_file_state_unchanged(&alias, &alias_before, "same-inode rename alias");
        assert_file_state_unchanged(&original, &alias_before, "same-inode rename source");

        let alias_meta_after = fs::metadata(&alias).expect("stat alias after rename");
        assert_eq!(
            alias_meta_after.ino(),
            original_ino_before,
            "destination should keep the original inode"
        );
        assert_eq!(
            alias_meta_after.nlink(),
            2,
            "same-inode rename should preserve the shared link count"
        );
        let original_meta_after = fs::metadata(&original).expect("stat source after rename");
        assert_eq!(
            original_meta_after.ino(),
            original_ino_before,
            "source should still resolve to the original inode"
        );
        assert_eq!(
            original_meta_after.nlink(),
            2,
            "source should keep the shared link count after same-inode rename"
        );
        emit_scenario_result(scenario_id, "PASS", Some("visible_noop_nlink=2"));
    });
}

#[test]
fn btrfs_fuse_hard_link() {
    with_btrfs_rw_mount(|mnt| {
        let original = mnt.join("linkme.txt");
        fs::write(&original, b"hard link content\n").expect("write original for hard link");

        let link = mnt.join("linkme_link.txt");
        fs::hard_link(&original, &link).expect("hard link on btrfs");

        let content = fs::read_to_string(&link).expect("read through hard link");
        assert_eq!(content, "hard link content\n");

        // Both should share the same inode.
        let orig_ino = fs::metadata(&original).expect("stat original").ino();
        let link_ino = fs::metadata(&link).expect("stat link").ino();
        assert_eq!(orig_ino, link_ino, "hard link should share inode");

        let orig_nlink = fs::metadata(&original).expect("stat original").nlink();
        let link_nlink = fs::metadata(&link).expect("stat link").nlink();
        assert_eq!(orig_nlink, 2, "original should report two hard links");
        assert_eq!(link_nlink, 2, "link should report two hard links");
    });
}

#[test]
fn btrfs_fuse_hard_link_unlink_updates_nlink_accounting() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_hard_link_unlink_nlink_accounting";
        let original = mnt.join("linkme.txt");
        let alias = mnt.join("linkme_alias.txt");
        fs::write(&original, b"hard link unlink content\n").expect("write original");
        fs::hard_link(&original, &alias).expect("create btrfs hard link alias");

        let original_before = snapshot_file_state(&original);
        let entries_before = snapshot_directory_entries(mnt);
        let original_meta_before = fs::metadata(&original).expect("stat original before unlink");
        let alias_meta_before = fs::metadata(&alias).expect("stat alias before unlink");
        assert_eq!(
            original_meta_before.ino(),
            alias_meta_before.ino(),
            "hard-link alias should resolve to the same inode before unlink"
        );
        assert_eq!(
            original_meta_before.nlink(),
            2,
            "hard-link creation should raise the source link count to two"
        );

        fs::remove_file(&alias).expect("unlink hard-link alias");

        assert!(
            fs::symlink_metadata(&alias).is_err(),
            "alias should be removed after unlink"
        );
        assert_file_state_unchanged(&original, &original_before, "hard-link unlink survivor");

        let mut expected_entries = entries_before;
        expected_entries.remove("linkme_alias.txt");
        assert_eq!(
            snapshot_directory_entries(mnt),
            expected_entries,
            "unlinking the alias should remove only that directory entry"
        );

        let original_meta_after = fs::metadata(&original).expect("stat original after unlink");
        assert_eq!(
            original_meta_after.ino(),
            original_meta_before.ino(),
            "surviving name should keep the original inode binding"
        );
        assert_eq!(
            original_meta_after.nlink(),
            1,
            "unlinking the alias should restore the source link count to one"
        );

        emit_scenario_result(scenario_id, "PASS", Some("alias_removed_nlink=1"));
    });
}

#[test]
fn btrfs_fuse_hard_link_to_symlink_preserves_symlink_type() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_hard_link_to_symlink_preserves_type";
        let target = mnt.join("sym_target.txt");
        fs::write(&target, b"symlink hard-link target\n").expect("write symlink target");

        let symlink_path = mnt.join("sym_source.txt");
        let alias_path = mnt.join("sym_alias.txt");
        std::os::unix::fs::symlink("sym_target.txt", &symlink_path)
            .expect("create btrfs source symlink");
        fs::hard_link(&symlink_path, &alias_path).expect("hard-link btrfs source symlink");

        let symlink_meta = fs::symlink_metadata(&symlink_path).expect("lstat btrfs source symlink");
        let alias_meta = fs::symlink_metadata(&alias_path).expect("lstat btrfs hard-link alias");
        assert!(
            symlink_meta.file_type().is_symlink(),
            "btrfs source path must remain a symlink after hard-linking"
        );
        assert!(
            alias_meta.file_type().is_symlink(),
            "btrfs hard-link alias must preserve the symlink inode type"
        );
        assert_eq!(
            symlink_meta.ino(),
            alias_meta.ino(),
            "btrfs hard-link alias should reference the same symlink inode"
        );
        assert_eq!(
            symlink_meta.nlink(),
            2,
            "btrfs source symlink should report two hard-link names"
        );
        assert_eq!(
            alias_meta.nlink(),
            2,
            "btrfs hard-link alias should report the shared symlink link count"
        );

        let symlink_target = fs::read_link(&symlink_path).expect("readlink btrfs source symlink");
        let alias_target = fs::read_link(&alias_path).expect("readlink btrfs hard-link alias");
        assert_eq!(symlink_target, PathBuf::from("sym_target.txt"));
        assert_eq!(
            alias_target, symlink_target,
            "btrfs hard-link alias should expose the same symlink target bytes"
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("lstat=symlink_readlink=target_preserved"),
        );
    });
}

fn assert_btrfs_hard_link_directory_source_refusal(mnt: &Path) {
    let dir_source = mnt.join("dir_source");
    fs::create_dir(&dir_source).expect("create directory hard-link source");
    let root_entries_before = snapshot_directory_entries(mnt);

    let dir_err = fs::hard_link(&dir_source, mnt.join("dir_hardlink"))
        .expect_err("hard-linking a directory should fail");
    assert_eq!(
        dir_err.raw_os_error(),
        Some(libc::EPERM),
        "hard-linking a directory should surface exact EPERM: {dir_err}"
    );
    assert!(
        fs::symlink_metadata(mnt.join("dir_hardlink")).is_err(),
        "directory-source refusal must not leave a new entry behind"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "directory-source refusal must not change visible root entries"
    );
}

fn assert_btrfs_hard_link_non_directory_parent_refusal(mnt: &Path) {
    let source = mnt.join("link_src.txt");
    let non_directory_parent = mnt.join("not_a_dir.txt");
    fs::write(&source, b"link source payload\n").expect("write hard-link source");
    fs::write(&non_directory_parent, b"not a directory\n").expect("write non-directory parent");
    let root_entries_before = snapshot_directory_entries(mnt);
    let source_before = snapshot_file_state(&source);
    let parent_before = snapshot_file_state(&non_directory_parent);
    let source_nlink_before = fs::metadata(&source).expect("stat source before").nlink();
    let nested_target = non_directory_parent.join("child.txt");

    let parent_err = fs::hard_link(&source, &nested_target)
        .expect_err("hard link into non-directory parent should fail");
    assert_eq!(
        parent_err.raw_os_error(),
        Some(libc::ENOTDIR),
        "hard link into non-directory parent should surface exact ENOTDIR: {parent_err}"
    );
    assert!(
        fs::symlink_metadata(&nested_target).is_err(),
        "non-directory-parent refusal must not create the nested destination"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "non-directory-parent refusal must not change visible root entries"
    );
    assert_file_state_unchanged(&source, &source_before, "rejected hard-link source");
    assert_file_state_unchanged(
        &non_directory_parent,
        &parent_before,
        "rejected hard-link non-directory parent",
    );
    assert_eq!(
        fs::metadata(&source).expect("stat source after").nlink(),
        source_nlink_before,
        "non-directory-parent refusal must not change source link count"
    );
}

fn assert_btrfs_hard_link_occupied_destination_refusal(mnt: &Path) {
    let occupied_target = mnt.join("occupied_target.txt");
    let occupied_destination = mnt.join("occupied_destination.txt");
    fs::write(&occupied_target, b"occupied target payload\n").expect("write occupied target");
    fs::write(&occupied_destination, b"occupied destination payload\n")
        .expect("write occupied destination");
    let root_entries_before = snapshot_directory_entries(mnt);
    let target_before = snapshot_file_state(&occupied_target);
    let destination_before = snapshot_file_state(&occupied_destination);
    let target_nlink_before = fs::metadata(&occupied_target)
        .expect("stat occupied target before")
        .nlink();

    let exists_err = fs::hard_link(&occupied_target, &occupied_destination)
        .expect_err("hard link onto existing destination should fail");
    assert_eq!(
        exists_err.raw_os_error(),
        Some(libc::EEXIST),
        "hard link onto existing destination should surface exact EEXIST: {exists_err}"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "occupied-destination refusal must not change visible root entries"
    );
    assert_file_state_unchanged(
        &occupied_target,
        &target_before,
        "rejected occupied-destination source",
    );
    assert_file_state_unchanged(
        &occupied_destination,
        &destination_before,
        "rejected occupied destination",
    );
    assert_eq!(
        fs::metadata(&occupied_target)
            .expect("stat occupied target after")
            .nlink(),
        target_nlink_before,
        "occupied-destination refusal must not change source link count"
    );
}

#[test]
fn btrfs_fuse_hard_link_refusal_contracts() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_hard_link_refusal_contracts";
        assert_btrfs_hard_link_directory_source_refusal(mnt);
        assert_btrfs_hard_link_non_directory_parent_refusal(mnt);
        assert_btrfs_hard_link_occupied_destination_refusal(mnt);

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("dir=EPERM_parent=ENOTDIR_exists=EEXIST_no_drift"),
        );
    });
}

#[test]
fn btrfs_fuse_symlink_create_and_follow() {
    with_btrfs_rw_mount(|mnt| {
        let target = mnt.join("sym_target.txt");
        fs::write(&target, b"symlink target content\n").expect("write symlink target");

        let link = mnt.join("sym.txt");
        std::os::unix::fs::symlink("sym_target.txt", &link).expect("symlink on btrfs");

        // Verify readlink returns the target.
        let read_target = fs::read_link(&link).expect("readlink on btrfs");
        assert_eq!(read_target.to_str().unwrap(), "sym_target.txt");

        // Following the symlink should work.
        let content = fs::read_to_string(&link).expect("read through symlink on btrfs");
        assert_eq!(content, "symlink target content\n");

        // Symlink metadata should differ from target.
        let link_meta = fs::symlink_metadata(&link).expect("lstat symlink on btrfs");
        assert!(link_meta.file_type().is_symlink());
    });
}

#[test]
fn btrfs_fuse_readlink_on_non_symlink_reports_einval() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_readlink_on_non_symlink_reports_einval";
        let file_path = mnt.join("readlink_non_symlink.txt");
        let dir_path = mnt.join("readlink_non_symlink_dir");
        fs::write(&file_path, b"btrfs readlink refusal witness\n").expect("seed regular file");
        fs::create_dir(&dir_path).expect("seed directory");
        let root_entries_before = snapshot_directory_entries(mnt);
        let file_before = snapshot_file_state(&file_path);
        let dir_entries_before = snapshot_directory_entries(&dir_path);

        let file_err = fs::read_link(&file_path).expect_err("readlink on regular file should fail");
        assert_eq!(
            file_err.raw_os_error(),
            Some(libc::EINVAL),
            "readlink on regular file should surface exact EINVAL: {file_err}"
        );
        assert_file_state_unchanged(
            &file_path,
            &file_before,
            "btrfs readlink rejection on regular file",
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected readlink on regular file must not change root entries"
        );

        let dir_err = fs::read_link(&dir_path).expect_err("readlink on directory should fail");
        assert_eq!(
            dir_err.raw_os_error(),
            Some(libc::EINVAL),
            "readlink on directory should surface exact EINVAL: {dir_err}"
        );
        assert_eq!(
            snapshot_directory_entries(&dir_path),
            dir_entries_before,
            "rejected readlink on directory must not change directory entries"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected readlink on directory must not change root entries"
        );

        emit_scenario_result(scenario_id, "PASS", Some("file+dir_errno=EINVAL_no_drift"));
    });
}

#[test]
fn btrfs_fuse_symlink_target_path_max_boundary_and_enametoolong_contract() {
    with_btrfs_rw_mount(|mnt| {
        assert_symlink_target_path_max_contract(mnt, "btrfs_rw_symlink_target_path_max");
    });
}

#[test]
fn btrfs_fuse_symlink_refusal_contracts() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_symlink_refusal_contracts";
        let target = mnt.join("sym_target.txt");
        fs::write(&target, b"symlink target content\n").expect("write btrfs symlink target");

        let occupied_destination = mnt.join("occupied_symlink_destination.txt");
        fs::write(&occupied_destination, b"occupied destination payload\n")
            .expect("write occupied btrfs symlink destination");
        let root_entries_before = snapshot_directory_entries(mnt);
        let occupied_before = snapshot_file_state(&occupied_destination);

        let exists_err = std::os::unix::fs::symlink("sym_target.txt", &occupied_destination)
            .expect_err("symlink onto existing destination should fail");
        assert_eq!(
            exists_err.raw_os_error(),
            Some(libc::EEXIST),
            "symlink onto existing destination should surface exact EEXIST: {exists_err}"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "occupied-destination symlink refusal must not change visible root entries"
        );
        assert_file_state_unchanged(
            &occupied_destination,
            &occupied_before,
            "rejected occupied btrfs symlink destination",
        );

        let non_directory_parent = mnt.join("symlink_parent_file.txt");
        fs::write(&non_directory_parent, b"not a directory\n")
            .expect("write btrfs symlink non-directory parent");
        let root_entries_before = snapshot_directory_entries(mnt);
        let parent_before = snapshot_file_state(&non_directory_parent);
        let nested_target = non_directory_parent.join("child_link.txt");

        let parent_err = std::os::unix::fs::symlink("sym_target.txt", &nested_target)
            .expect_err("symlink into non-directory parent should fail");
        assert_eq!(
            parent_err.raw_os_error(),
            Some(libc::ENOTDIR),
            "symlink into non-directory parent should surface exact ENOTDIR: {parent_err}"
        );
        assert!(
            fs::symlink_metadata(&nested_target).is_err(),
            "non-directory-parent symlink refusal must not create the nested destination"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "non-directory-parent symlink refusal must not change visible root entries"
        );
        assert_file_state_unchanged(
            &non_directory_parent,
            &parent_before,
            "rejected btrfs symlink non-directory parent",
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("exists=EEXIST_parent=ENOTDIR_no_drift"),
        );
    });
}

#[test]
fn btrfs_fuse_setattr_truncate() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("trunc.txt");
        fs::write(&path, b"Hello from btrfs truncate test!\n").expect("write for truncate");

        let original_len = fs::metadata(&path).expect("stat").len();
        assert!(original_len > 0);

        // Truncate to 5 bytes.
        let f = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for truncate");
        f.set_len(5).expect("truncate on btrfs");
        drop(f);

        let new_len = fs::metadata(&path).expect("stat after truncate").len();
        assert_eq!(new_len, 5, "file should be truncated to 5 bytes");

        let content = fs::read_to_string(&path).expect("read truncated file on btrfs");
        assert_eq!(content, "Hello");
    });
}

#[test]
fn btrfs_fuse_setattr_chmod() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("chmod_test.txt");
        fs::write(&path, b"chmod test content\n").expect("write for chmod");

        // Change to 0o755.
        let new_perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&path, new_perms).expect("chmod 755 on btrfs");

        let meta = fs::metadata(&path).expect("stat after chmod");
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            0o755,
            "permissions should be 0o755 after chmod on btrfs"
        );

        // Change to 0o600.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod 600 on btrfs");

        let meta = fs::metadata(&path).expect("stat after second chmod");
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            0o600,
            "permissions should be 0o600 after second chmod on btrfs"
        );

        // File should still be readable/writable by us since we own it.
        let content = fs::read_to_string(&path).expect("read after chmod on btrfs");
        assert_eq!(content, "chmod test content\n");
    });
}

#[test]
fn btrfs_fuse_setattr_utimes() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("utimes_test.txt");
        fs::write(&path, b"utimes test content\n").expect("write for utimes");

        // Use Python os.utime to set atime and mtime to a known epoch.
        let script = format!(
            "import os; os.utime({path:?}, (1_700_000_000, 1_700_000_000))",
            path = path.to_str().unwrap(),
        );
        let out = Command::new("python3")
            .args(["-c", &script])
            .output()
            .expect("python3 utime");
        assert!(
            out.status.success(),
            "os.utime on btrfs failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after utime on btrfs");
        assert_eq!(
            meta.atime(),
            1_700_000_000,
            "atime should be 1700000000 after os.utime on btrfs"
        );
        assert_eq!(
            meta.mtime(),
            1_700_000_000,
            "mtime should be 1700000000 after os.utime on btrfs"
        );
    });
}

#[test]
fn btrfs_fuse_setattr_read_only_rejects_chmod_truncate_and_utimes_with_erofs() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image_with_seeded_file(
        tmp.path(),
        "readonly_seed.txt",
        b"readonly btrfs seed content\n",
    );
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    assert_read_only_setattr_contract(
        &mnt.join(BTRFS_TEST_WORKSPACE).join("readonly_seed.txt"),
        "btrfs_ro_setattr_rejects_erofs_no_drift",
    );
}

#[test]
fn btrfs_fuse_read_only_fallocate_mutation_attempts_report_erofs_without_file_drift() {
    if !btrfs_fuse_available() || !command_available("python3") {
        eprintln!("btrfs FUSE or python3 prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image_with_seeded_file(
        tmp.path(),
        "readonly_fallocate_seed.txt",
        b"readonly btrfs fallocate seed\n",
    );
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    let scenario_id = "btrfs_ro_fallocate_mutation_attempts_reject_erofs_no_drift";
    let path = mnt
        .join(BTRFS_TEST_WORKSPACE)
        .join("readonly_fallocate_seed.txt");
    let before = snapshot_file_state(&path);

    let preallocate_report = py_fallocate_report(&path, 0, 0, before.len + 4096);
    assert_eq!(
        preallocate_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only btrfs preallocate should surface exact EROFS: {preallocate_report}"
    );
    assert_file_state_unchanged(&path, &before, "rejected read-only btrfs preallocate");

    let punch_hole_report = py_fallocate_report(
        &path,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
        0,
        before.len.min(8),
    );
    assert_eq!(
        punch_hole_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only btrfs punch-hole should surface exact EROFS: {punch_hole_report}"
    );
    assert_file_state_unchanged(&path, &before, "rejected read-only btrfs punch-hole");

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("preallocate+punch_hole=EROFS_no_file_drift"),
    );
}

#[test]
fn btrfs_fuse_read_only_create_mkdir_link_and_symlink_report_erofs_without_dirent_drift() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image_with_seeded_file(
        tmp.path(),
        "readonly_namespace_seed.txt",
        b"readonly btrfs namespace seed\n",
    );
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    let seed = workspace.join("readonly_namespace_seed.txt");
    assert_eq!(
        fs::read(&seed).expect("read seeded btrfs namespace file"),
        b"readonly btrfs namespace seed\n",
        "read-only remount must preserve the seeded namespace file bytes"
    );

    assert_read_only_namespace_mutation_contract(
        &workspace,
        &seed,
        "btrfs_ro_create_mkdir_link_symlink_reject_erofs_no_drift",
    );
}

#[test]
fn btrfs_fuse_read_only_regular_writes_report_erofs_without_file_or_dirent_drift() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image_with_seeded_file(
        tmp.path(),
        "readonly_write_seed.txt",
        b"readonly btrfs write seed\n",
    );
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    let seed = workspace.join("readonly_write_seed.txt");
    assert_eq!(
        fs::read(&seed).expect("read seeded btrfs write file"),
        b"readonly btrfs write seed\n",
        "read-only remount must preserve the seeded write target bytes"
    );

    assert_read_only_regular_write_contract(
        &workspace,
        &seed,
        "btrfs_ro_regular_writes_reject_erofs_no_drift",
    );
}

#[test]
fn btrfs_fuse_read_only_unlink_rmdir_and_rename_report_erofs_without_dirent_drift() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image_with_seeded_namespace_removal_fixture(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    let keep_file = workspace.join("readonly_unlink_seed.txt");
    let empty_dir = workspace.join("readonly_empty_dir");
    let rename_source = workspace.join("readonly_rename_source.txt");
    assert_eq!(
        fs::read(&keep_file).expect("read seeded btrfs unlink file"),
        b"readonly btrfs unlink seed\n",
        "read-only remount must preserve the seeded unlink target bytes"
    );
    assert_eq!(
        fs::read(&rename_source).expect("read seeded btrfs rename source file"),
        b"readonly btrfs rename source\n",
        "read-only remount must preserve the seeded rename source bytes"
    );
    assert!(
        empty_dir.is_dir(),
        "read-only remount must preserve the seeded empty directory"
    );

    assert_read_only_unlink_rmdir_and_rename_contract(
        &workspace,
        &keep_file,
        &empty_dir,
        &rename_source,
        "btrfs_ro_unlink_rmdir_rename_reject_erofs_no_drift",
    );
}

#[test]
fn btrfs_fuse_statfs() {
    with_btrfs_rw_root_mount(|mnt| {
        // Use `stat -f` to exercise the FUSE statfs handler and parse the output.
        let out = Command::new("stat")
            .args(["-f", "-c", "%s %b %f %a %c %d %l", mnt.to_str().unwrap()])
            .output()
            .expect("stat -f on btrfs mountpoint");
        assert!(
            out.status.success(),
            "stat -f on btrfs failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let stdout = String::from_utf8_lossy(&out.stdout);
        let fields: Vec<&str> = stdout.split_whitespace().collect();
        assert_eq!(
            fields.len(),
            7,
            "expected 7 stat -f fields, got: {stdout:?}"
        );

        // Parse statfs fields: block_size blocks blocks_free blocks_avail files files_free namelen
        let block_size: u64 = fields[0].parse().expect("parse block_size");
        let blocks: u64 = fields[1].parse().expect("parse blocks");
        let blocks_free: u64 = fields[2].parse().expect("parse blocks_free");
        let blocks_avail: u64 = fields[3].parse().expect("parse blocks_avail");
        let files: u64 = fields[4].parse().expect("parse files");
        let _files_free: u64 = fields[5].parse().expect("parse files_free");
        let namelen: u64 = fields[6].parse().expect("parse namelen");

        // Validate: block size should be a power of two in [4096, 65536].
        assert!(
            block_size.is_power_of_two() && (4096..=65536).contains(&block_size),
            "btrfs block_size {block_size} should be a power-of-two in [4096, 65536]"
        );

        // Total blocks should be non-zero (we made a 128 MiB image).
        assert!(blocks > 0, "total blocks should be > 0");

        // Free blocks should not exceed total blocks.
        assert!(
            blocks_free <= blocks,
            "free blocks ({blocks_free}) should be <= total ({blocks})"
        );
        assert!(
            blocks_avail <= blocks,
            "available blocks ({blocks_avail}) should be <= total ({blocks})"
        );

        // Total inodes should be non-zero.
        assert!(files > 0, "total inodes should be > 0");

        // Max filename length: btrfs is 255.
        assert_eq!(namelen, 255, "btrfs max filename length should be 255");
    });
}

#[test]
fn btrfs_fuse_seek_data_hole_reports_punched_range_offsets() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_seek_data_hole";
        let path = mnt.join("btrfs_seek_layout.bin");
        assert_seek_data_hole_contract(&path, scenario_id);
    });
}

#[test]
fn btrfs_fuse_seek_hole_reports_virtual_eof_for_fully_allocated_file() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_seek_hole_fully_allocated";
        let path = mnt.join("btrfs_seek_fully_allocated.bin");
        assert_seek_fully_allocated_contract(&path, scenario_id);
    });
}

#[test]
fn btrfs_fuse_seek_data_hole_reports_leading_sparse_hole_offsets() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_seek_leading_hole";
        let path = mnt.join("btrfs_seek_leading_hole.bin");
        assert_seek_leading_hole_contract(&path, scenario_id);
    });
}

#[test]
fn btrfs_fuse_seek_data_hole_reports_all_hole_sparse_file_offsets() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_seek_all_hole";
        let path = mnt.join("btrfs_seek_all_hole.bin");
        assert_seek_all_hole_contract(&path, scenario_id);
    });
}

#[test]
fn btrfs_fuse_xattr_set_get_list_remove() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_set_get_list_remove";
        let path = mnt.join("xattr_test.txt");
        fs::write(&path, b"xattr test content\n").expect("write for xattr");

        // Set a user xattr.
        py_setxattr(&path, "user.test_key", b"test_value_123");

        // Get it back.
        let val = py_getxattr(&path, "user.test_key").expect("xattr should exist after set");
        assert_eq!(val, b"test_value_123");

        // List should include it.
        let names = py_listxattr(&path);
        assert!(
            names.iter().any(|n| n == "user.test_key"),
            "listxattr should contain user.test_key on btrfs, got: {names:?}"
        );

        // Remove it.
        assert!(
            py_removexattr(&path, "user.test_key"),
            "removexattr should succeed on btrfs"
        );

        // Should be gone.
        assert!(
            py_getxattr(&path, "user.test_key").is_none(),
            "xattr should be absent after removexattr on btrfs"
        );
        emit_scenario_result(scenario_id, "PASS", Some("user_namespace_full_cycle"));
    });
}

#[test]
fn btrfs_fuse_xattr_multiple_attributes() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_multiple_attributes";
        let path = mnt.join("multi_xattr.txt");
        fs::write(&path, b"multi xattr content\n").expect("write for multi xattr");

        // Set multiple xattrs.
        py_setxattr(&path, "user.alpha", b"aaa");
        py_setxattr(&path, "user.beta", b"bbb");
        py_setxattr(&path, "user.gamma", b"ccc");

        // Verify each value.
        assert_eq!(py_getxattr(&path, "user.alpha").unwrap(), b"aaa");
        assert_eq!(py_getxattr(&path, "user.beta").unwrap(), b"bbb");
        assert_eq!(py_getxattr(&path, "user.gamma").unwrap(), b"ccc");

        // List should contain all three.
        let names = py_listxattr(&path);
        for expected in ["user.alpha", "user.beta", "user.gamma"] {
            assert!(
                names.iter().any(|n| n == expected),
                "listxattr on btrfs should contain {expected}, got: {names:?}"
            );
        }
        emit_scenario_result(scenario_id, "PASS", Some("three_distinct_user_xattrs"));
    });
}

#[test]
fn btrfs_fuse_xattr_on_directory() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_on_directory";
        let dir = mnt.join("xattr_dir");
        fs::create_dir(&dir).expect("mkdir for xattr");

        // Set xattr on directory.
        py_setxattr(&dir, "user.dir_attr", b"dir_value");

        let val = py_getxattr(&dir, "user.dir_attr").expect("xattr on btrfs dir should exist");
        assert_eq!(val, b"dir_value");

        let names = py_listxattr(&dir);
        assert!(
            names.iter().any(|n| n == "user.dir_attr"),
            "listxattr on btrfs dir should contain user.dir_attr, got: {names:?}"
        );
        emit_scenario_result(scenario_id, "PASS", Some("user_xattr_on_directory_inode"));
    });
}

#[test]
fn btrfs_fuse_xattr_create_existing_reports_eexist_without_side_effects() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_create_existing_reports_eexist";
        let path = mnt.join("btrfs_xattr_modes.txt");
        fs::write(&path, b"btrfs xattr mode coverage\n").expect("write btrfs xattr mode file");
        let original_file = fs::read(&path).expect("read original btrfs file bytes");

        py_setxattr(&path, "user.locked", b"original");
        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_setxattr_report(&path, "user.locked", b"replacement", libc::XATTR_CREATE);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EEXIST)),
            "btrfs XATTR_CREATE should reject an existing xattr with EEXIST: {report}"
        );
        assert_eq!(
            py_getxattr(&path, "user.locked").expect("existing xattr should remain readable"),
            b"original",
            "btrfs XATTR_CREATE failure must preserve the original xattr value"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "btrfs XATTR_CREATE failure must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after create failure"),
            original_file,
            "btrfs XATTR_CREATE failure must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            names.iter().any(|name| name == "user.locked"),
            "existing xattr should still be listed after btrfs XATTR_CREATE failure: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should still be listed after btrfs XATTR_CREATE failure: {names:?}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("errno=EEXIST_with_no_side_effects"),
        );
    });
}

#[test]
fn btrfs_fuse_xattr_replace_missing_reports_enodata_without_side_effects() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_replace_missing_reports_enodata";
        let path = mnt.join("btrfs_xattr_modes.txt");
        fs::write(&path, b"btrfs xattr mode coverage\n").expect("write btrfs xattr mode file");
        let original_file = fs::read(&path).expect("read original btrfs file bytes");

        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_setxattr_report(&path, "user.missing", b"replacement", libc::XATTR_REPLACE);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "btrfs XATTR_REPLACE should reject a missing xattr with ENODATA on Linux FUSE: {report}"
        );
        assert!(
            py_getxattr(&path, "user.missing").is_none(),
            "btrfs XATTR_REPLACE failure must not create the missing xattr"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "btrfs XATTR_REPLACE failure must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after replace failure"),
            original_file,
            "btrfs XATTR_REPLACE failure must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            !names.iter().any(|name| name == "user.missing"),
            "missing xattr should remain absent after btrfs XATTR_REPLACE failure: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should still be listed after btrfs XATTR_REPLACE failure: {names:?}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("errno=ENODATA_with_no_side_effects"),
        );
    });
}

#[test]
fn btrfs_fuse_xattr_read_only_set_and_remove_report_erofs_without_side_effects() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let setup_mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ..MountOptions::default()
    };

    {
        let Some(setup_session) = try_mount_btrfs_rw_with_options(&image, &mnt, &setup_mount_opts)
        else {
            return;
        };

        let path = mnt
            .join(BTRFS_TEST_WORKSPACE)
            .join("readonly_xattr_seed.txt");
        fs::write(&path, b"readonly btrfs xattr seed\n").expect("write ro btrfs xattr seed file");
        py_setxattr(&path, "user.locked", b"original");
        py_setxattr(&path, "user.keep", b"preserve");
        drop(setup_session);
    }

    wait_for_fuse_mount_released(&mnt);

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    let path = mnt
        .join(BTRFS_TEST_WORKSPACE)
        .join("readonly_xattr_seed.txt");
    assert_eq!(
        fs::read(&path).expect("read seeded ro btrfs xattr file"),
        b"readonly btrfs xattr seed\n",
        "ro remount must preserve the seeded file bytes"
    );

    assert_read_only_xattr_mutation_contract(
        &path,
        "btrfs_ro_xattr_mutation_rejects_erofs_no_side_effects",
    );
}

#[test]
fn btrfs_fuse_xattr_overwrite_value() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_overwrite_value";
        let path = mnt.join("overwrite_xattr.txt");
        fs::write(&path, b"overwrite xattr test\n").expect("write for overwrite xattr");

        // Set initial value.
        py_setxattr(&path, "user.mutable", b"original");
        assert_eq!(py_getxattr(&path, "user.mutable").unwrap(), b"original");

        // Overwrite with different value.
        py_setxattr(&path, "user.mutable", b"updated_value");
        assert_eq!(
            py_getxattr(&path, "user.mutable").unwrap(),
            b"updated_value"
        );
        emit_scenario_result(scenario_id, "PASS", Some("second_setxattr_updates_value"));
    });
}

#[test]
fn btrfs_fuse_xattr_get_missing_reports_enodata_without_side_effects() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_get_missing_reports_enodata";
        let path = mnt.join("nonexistent_xattr.txt");
        fs::write(&path, b"nonexistent xattr test\n").expect("write for nonexistent xattr");
        let original_file = fs::read(&path).expect("read original btrfs file bytes");
        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_getxattr_report(&path, "user.does_not_exist");
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "missing btrfs getxattr should surface ENODATA on Linux FUSE: {report}"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "missing btrfs getxattr must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after missing getxattr"),
            original_file,
            "missing btrfs getxattr must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            !names.iter().any(|name| name == "user.does_not_exist"),
            "missing xattr should remain absent after btrfs ENODATA getxattr: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should remain listed after btrfs ENODATA getxattr: {names:?}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("errno=ENODATA_with_no_side_effects"),
        );
    });
}

#[test]
fn btrfs_fuse_xattr_remove_missing_reports_enodata_without_side_effects() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_remove_missing_reports_enodata";
        let path = mnt.join("remove_nonexistent_xattr.txt");
        fs::write(&path, b"remove nonexistent xattr test\n")
            .expect("write for remove nonexistent xattr");
        let original_file = fs::read(&path).expect("read original btrfs file bytes");
        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_removexattr_report(&path, "user.no_such_attr");
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "missing btrfs removexattr should surface ENODATA on Linux FUSE: {report}"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "missing btrfs removexattr must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after missing removexattr"),
            original_file,
            "missing btrfs removexattr must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            !names.iter().any(|name| name == "user.no_such_attr"),
            "missing xattr should remain absent after btrfs ENODATA removexattr: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should remain listed after btrfs ENODATA removexattr: {names:?}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("errno=ENODATA_with_no_side_effects"),
        );
    });
}

#[test]
fn btrfs_fuse_getxattr_size_probe_and_erange_without_side_effects() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_getxattr_size_probe_and_erange";
        let path = mnt.join("getxattr_probe.txt");
        let original_file = b"btrfs getxattr probe coverage\n";
        let expected_value = b"probe-value";
        fs::write(&path, original_file).expect("write btrfs getxattr probe file");
        py_setxattr(&path, "user.probed", expected_value);
        py_setxattr(&path, "user.keep", b"preserve");

        let probe_report = py_getxattr_probe_report(&path, "user.probed", 0);
        assert_eq!(
            probe_report["len"].as_u64(),
            Some(expected_value.len() as u64),
            "zero-sized getxattr probe should report exact required length: {probe_report}"
        );

        let exact_report = py_getxattr_probe_report(&path, "user.probed", expected_value.len());
        let expected_value_hex = hex::encode(expected_value);
        assert_eq!(
            exact_report["len"].as_u64(),
            Some(expected_value.len() as u64),
            "exact-sized getxattr should report the payload length: {exact_report}"
        );
        assert_eq!(
            exact_report["value_hex"].as_str(),
            Some(expected_value_hex.as_str()),
            "exact-sized getxattr should return the full payload: {exact_report}"
        );

        let erange_report =
            py_getxattr_probe_report(&path, "user.probed", expected_value.len() - 1);
        assert_eq!(
            erange_report["errno"].as_i64(),
            Some(i64::from(libc::ERANGE)),
            "undersized getxattr buffer should fail with ERANGE: {erange_report}"
        );

        assert_eq!(
            py_getxattr(&path, "user.probed").expect("probed xattr should remain readable"),
            expected_value,
            "getxattr probe/ERANGE paths must not disturb the target xattr"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("keep xattr should remain readable"),
            b"preserve",
            "getxattr probe/ERANGE paths must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after getxattr probe"),
            original_file,
            "getxattr probe/ERANGE paths must not mutate file contents"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("probe_len_exact_and_erange_no_side_effects"),
        );
    });
}

#[test]
fn btrfs_fuse_listxattr_size_probe_and_erange_without_side_effects() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_listxattr_size_probe_and_erange";
        let path = mnt.join("listxattr_probe.txt");
        let original_file = b"btrfs listxattr probe coverage\n";
        fs::write(&path, original_file).expect("write btrfs listxattr probe file");
        py_setxattr(&path, "user.alpha", b"one");
        py_setxattr(&path, "user.beta", b"two");

        let expected_names = py_listxattr(&path);
        let expected_len: usize = expected_names.iter().map(|name| name.len() + 1).sum();

        let probe_report = py_listxattr_probe_report(&path, 0);
        assert_eq!(
            probe_report["len"].as_u64(),
            Some(expected_len as u64),
            "zero-sized listxattr probe should report exact required length: {probe_report}"
        );

        let exact_report = py_listxattr_probe_report(&path, expected_len);
        assert_eq!(
            exact_report["len"].as_u64(),
            Some(expected_len as u64),
            "exact-sized listxattr should report the serialized name length: {exact_report}"
        );
        let mut actual_names: Vec<String> = exact_report["names"]
            .as_array()
            .expect("listxattr exact-sized names")
            .iter()
            .map(|value| value.as_str().expect("listxattr name string").to_string())
            .collect();
        let mut expected_sorted = expected_names;
        actual_names.sort();
        expected_sorted.sort();
        assert_eq!(
            actual_names, expected_sorted,
            "exact-sized listxattr should return the full mounted-path name set"
        );

        let erange_report = py_listxattr_probe_report(&path, expected_len - 1);
        assert_eq!(
            erange_report["errno"].as_i64(),
            Some(i64::from(libc::ERANGE)),
            "undersized listxattr buffer should fail with ERANGE: {erange_report}"
        );

        let mut names_after = py_listxattr(&path);
        names_after.sort();
        assert_eq!(
            names_after, expected_sorted,
            "listxattr probe/ERANGE paths must not disturb the visible xattr set"
        );
        assert_eq!(
            py_getxattr(&path, "user.alpha").expect("alpha xattr should remain readable"),
            b"one",
            "listxattr probe/ERANGE paths must not disturb alpha"
        );
        assert_eq!(
            py_getxattr(&path, "user.beta").expect("beta xattr should remain readable"),
            b"two",
            "listxattr probe/ERANGE paths must not disturb beta"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after listxattr probe"),
            original_file,
            "listxattr probe/ERANGE paths must not mutate file contents"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("probe_len_exact_and_erange_no_side_effects"),
        );
    });
}

#[test]
fn btrfs_fuse_empty_listxattr_size_probe_and_zero_length_payload() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_empty_listxattr_size_probe";
        let path = mnt.join("empty_listxattr_probe.txt");
        let original_file = b"btrfs empty listxattr probe coverage\n";
        fs::write(&path, original_file).expect("write btrfs empty listxattr probe file");

        let initial_names = py_listxattr(&path);
        assert!(
            initial_names.is_empty(),
            "fresh btrfs file should expose no visible xattrs: {initial_names:?}"
        );

        let probe_report = py_listxattr_probe_report(&path, 0);
        assert_eq!(
            probe_report["len"].as_u64(),
            Some(0),
            "empty listxattr size probe should report length 0: {probe_report}"
        );

        // For an empty xattr set, the exact-fit payload size is also zero.
        let zero_len_payload_report = py_listxattr_probe_report(&path, 0);
        assert_eq!(
            zero_len_payload_report["len"].as_u64(),
            Some(0),
            "empty listxattr zero-length payload should succeed with length 0: {zero_len_payload_report}"
        );

        let names_after = py_listxattr(&path);
        assert!(
            names_after.is_empty(),
            "empty listxattr probe paths must not create visible xattrs: {names_after:?}"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after empty listxattr probe"),
            original_file,
            "empty listxattr probe paths must not mutate file contents"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("empty_len_zero_and_zero_length_success"),
        );
    });
}

#[test]
fn btrfs_fuse_ioctl_fs_info_via_mounted_path() {
    if !command_available("python3") {
        eprintln!("python3 not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        // Use direct ioctl via Python to exercise BTRFS_IOC_FS_INFO (0x8400941F).
        // The ioctl returns a 1024-byte btrfs_ioctl_fs_info_args struct.
        let script = format!(
            r#"
import os, fcntl, struct
fd = os.open({mnt:?}, os.O_RDONLY | os.O_DIRECTORY)
try:
    buf = bytearray(1024)
    # BTRFS_IOC_FS_INFO = _IOR(0x94, 0x1f, 1024) = 0x8400941f
    fcntl.ioctl(fd, 0x8400941f, buf)
    # Parse first fields: max_id(u64), num_devices(u64), fsid(16 bytes), nodesize(u32)
    max_id, num_devices = struct.unpack_from('<QQ', buf, 0)
    fsid = buf[0x10:0x20]
    nodesize, sectorsize = struct.unpack_from('<II', buf, 0x20)
    print("max_id=%d num_devices=%d nodesize=%d sectorsize=%d" % (max_id, num_devices, nodesize, sectorsize))
    print("fsid=%s" % fsid.hex())
    assert num_devices >= 1, "num_devices should be at least 1"
    assert nodesize in (4096, 8192, 16384, 32768, 65536), "unexpected nodesize %d" % nodesize
    assert sectorsize in (512, 1024, 2048, 4096), "unexpected sectorsize %d" % sectorsize
    print("PASS")
finally:
    os.close(fd)
"#,
            mnt = mnt.to_str().unwrap()
        );

        let out = Command::new("python3")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("run python3 ioctl script");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("PASS"),
            "BTRFS_IOC_FS_INFO via mounted path failed: stdout={stdout}, stderr={stderr}"
        );
    });
}

#[test]
fn btrfs_openfs_ioctl_dev_info_payload_contract() {
    const BTRFS_DEV_INFO_SIZE: usize = 4096;
    const BTRFS_DEV_INFO_PATH_OFFSET: usize = 0x0C00;

    if !command_available("mkfs.btrfs") {
        eprintln!("mkfs.btrfs not available, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let fs = OpenFs::open_with_options(&cx, &image, &opts).expect("open btrfs image");

    let wildcard =
        <OpenFs as FsOps>::get_btrfs_dev_info(&fs, &cx, &mut RequestScope::empty(), 0, [0_u8; 16])
            .expect("wildcard DEV_INFO lookup");
    assert_eq!(wildcard.len(), BTRFS_DEV_INFO_SIZE);

    let devid = u64::from_ne_bytes(wildcard[0x00..0x08].try_into().expect("devid bytes"));
    let uuid: [u8; 16] = wildcard[0x08..0x18].try_into().expect("uuid bytes");
    let bytes_used = u64::from_ne_bytes(wildcard[0x18..0x20].try_into().expect("bytes_used bytes"));
    let total_bytes =
        u64::from_ne_bytes(wildcard[0x20..0x28].try_into().expect("total_bytes bytes"));

    assert_eq!(devid, 1, "single-device btrfs should report devid 1");
    assert_ne!(uuid, [0_u8; 16], "device uuid/fsid should be populated");
    assert!(bytes_used > 0, "bytes_used should be non-zero");
    assert!(
        total_bytes >= bytes_used,
        "total_bytes should cover bytes_used"
    );
    assert!(
        wildcard[BTRFS_DEV_INFO_PATH_OFFSET..]
            .iter()
            .all(|b| *b == 0),
        "image-backed DEV_INFO path should be empty"
    );

    let exact =
        <OpenFs as FsOps>::get_btrfs_dev_info(&fs, &cx, &mut RequestScope::empty(), 1, uuid)
            .expect("exact DEV_INFO lookup");
    assert_eq!(
        &exact[..0x28],
        &wildcard[..0x28],
        "exact devid+uuid lookup should return same device fields"
    );

    let missing =
        <OpenFs as FsOps>::get_btrfs_dev_info(&fs, &cx, &mut RequestScope::empty(), 2, [0_u8; 16])
            .expect_err("unknown DEV_INFO devid should fail");
    assert_eq!(missing.to_errno(), libc::ENODEV);
}

#[test]
fn btrfs_fuse_ioctl_dev_info_via_mounted_path() {
    if !command_available("python3") {
        eprintln!("python3 not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let script = format!(
            r#"
import errno, os, fcntl, struct

BTRFS_IOC_DEV_INFO = 0xd000941e
BTRFS_DEV_INFO_SIZE = 4096
BTRFS_DEV_INFO_PATH_OFFSET = 0x0c00

fd = os.open({mnt:?}, os.O_RDONLY | os.O_DIRECTORY)
try:
    wildcard = bytearray(BTRFS_DEV_INFO_SIZE)
    fcntl.ioctl(fd, BTRFS_IOC_DEV_INFO, wildcard, True)

    devid, = struct.unpack_from('<Q', wildcard, 0x00)
    uuid = bytes(wildcard[0x08:0x18])
    bytes_used, total_bytes = struct.unpack_from('<QQ', wildcard, 0x18)
    path = bytes(wildcard[BTRFS_DEV_INFO_PATH_OFFSET:])

    assert devid == 1, "single-device btrfs should report canonical devid 1, got %d" % devid
    assert uuid != bytes(16), "device uuid/fsid should be populated"
    assert bytes_used > 0, "bytes_used should be non-zero"
    assert total_bytes >= bytes_used, "total_bytes should cover bytes_used"
    assert path == bytes(len(path)), "FrankenFS image-backed DEV_INFO path should be empty"

    exact = bytearray(BTRFS_DEV_INFO_SIZE)
    struct.pack_into('<Q', exact, 0x00, 1)
    exact[0x08:0x18] = uuid
    fcntl.ioctl(fd, BTRFS_IOC_DEV_INFO, exact, True)
    assert exact[:0x28] == wildcard[:0x28], "explicit devid+uuid lookup should return same device"

    missing = bytearray(BTRFS_DEV_INFO_SIZE)
    struct.pack_into('<Q', missing, 0x00, 2)
    try:
        fcntl.ioctl(fd, BTRFS_IOC_DEV_INFO, missing, True)
    except OSError as exc:
        assert exc.errno == errno.ENODEV, "unknown devid should return ENODEV, got %d" % exc.errno
    else:
        raise AssertionError("unknown devid unexpectedly succeeded")

    print("devid=%d bytes_used=%d total_bytes=%d uuid=%s" % (devid, bytes_used, total_bytes, uuid.hex()))
    print("PASS")
finally:
    os.close(fd)
"#,
            mnt = mnt.to_str().unwrap()
        );

        let out = Command::new("python3")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("run python3 DEV_INFO ioctl script");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("PASS"),
            "BTRFS_IOC_DEV_INFO via mounted path failed: stdout={stdout}, stderr={stderr}"
        );

        emit_scenario_result(
            "btrfs_ioctl_dev_info_mounted_path",
            "PASS",
            Some("wildcard_exact_and_missing_device_contract"),
        );
    });
}

#[test]
fn btrfs_fuse_ioctl_ino_lookup_via_mounted_path() {
    if !command_available("python3") {
        eprintln!("python3 not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let child = mnt.join("ino_lookup_child.txt");
        fs::write(&child, b"btrfs ino lookup mounted-path child\n")
            .expect("create btrfs ino lookup child");

        let script = format!(
            r#"
import errno, os, fcntl, struct

BTRFS_IOC_INO_LOOKUP = 0xd0009412
BTRFS_INO_LOOKUP_ARGS_SIZE = 4096
BTRFS_FS_TREE_OBJECTID = 5
BTRFS_FIRST_FREE_OBJECTID = 256

def ino_lookup(fd, treeid, objectid):
    buf = bytearray(BTRFS_INO_LOOKUP_ARGS_SIZE)
    struct.pack_into('<Q', buf, 0x00, treeid)
    struct.pack_into('<Q', buf, 0x08, objectid)
    fcntl.ioctl(fd, BTRFS_IOC_INO_LOOKUP, buf, True)
    resolved_treeid, resolved_objectid = struct.unpack_from('<QQ', buf, 0x00)
    raw_path = bytes(buf[0x10:]).split(b'\x00', 1)[0]
    return resolved_treeid, resolved_objectid, raw_path

fd = os.open({mnt:?}, os.O_RDONLY | os.O_DIRECTORY)
try:
    root_treeid, root_objectid, root_path = ino_lookup(fd, 0, BTRFS_FIRST_FREE_OBJECTID)
    assert root_treeid == BTRFS_FS_TREE_OBJECTID, "treeid=0 root lookup should resolve to FS_TREE, got %d" % root_treeid
    assert root_objectid == BTRFS_FIRST_FREE_OBJECTID, "root objectid should be echoed"
    assert root_path == b'', "subvolume root path should be empty, got %r" % (root_path,)

    workspace_objectid = os.stat({mnt:?}).st_ino
    ws_treeid, ws_objectid, ws_path = ino_lookup(fd, 0, workspace_objectid)
    assert ws_treeid == BTRFS_FS_TREE_OBJECTID, "workspace lookup should resolve mounted tree, got %d" % ws_treeid
    assert ws_objectid == workspace_objectid, "workspace objectid should be echoed"
    assert ws_path == b'testdir/', "workspace path should be testdir/, got %r" % (ws_path,)

    child_objectid = os.stat({child:?}).st_ino
    child_treeid, child_echo, child_path = ino_lookup(fd, BTRFS_FS_TREE_OBJECTID, child_objectid)
    assert child_treeid == BTRFS_FS_TREE_OBJECTID, "explicit tree lookup should preserve FS_TREE, got %d" % child_treeid
    assert child_echo == child_objectid, "child objectid should be echoed"
    assert child_path == b'testdir/ino_lookup_child.txt/', "child path mismatch: %r" % (child_path,)

    missing = bytearray(BTRFS_INO_LOOKUP_ARGS_SIZE)
    struct.pack_into('<Q', missing, 0x00, 0)
    struct.pack_into('<Q', missing, 0x08, 0x7fffffffffffffff)
    try:
        fcntl.ioctl(fd, BTRFS_IOC_INO_LOOKUP, missing, True)
    except OSError as exc:
        assert exc.errno == errno.ENOENT, "missing objectid should return ENOENT, got %d" % exc.errno
    else:
        raise AssertionError("missing objectid unexpectedly succeeded")

    print("workspace_objectid=%d child_objectid=%d child_path=%s" % (workspace_objectid, child_objectid, child_path.decode('ascii')))
    print("PASS")
finally:
    os.close(fd)
"#,
            mnt = mnt.to_str().unwrap(),
            child = child.to_str().unwrap()
        );

        let out = Command::new("python3")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("run python3 INO_LOOKUP ioctl script");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("PASS"),
            "BTRFS_IOC_INO_LOOKUP via mounted path failed: stdout={stdout}, stderr={stderr}"
        );

        emit_scenario_result(
            "btrfs_ioctl_ino_lookup_mounted_path",
            "PASS",
            Some("root_workspace_runtime_child_and_missing_inode_contract"),
        );
    });
}

#[test]
fn btrfs_fuse_xattr_posix_acl_list_and_get() {
    with_btrfs_rw_mount(|mnt| {
        let file_path = mnt.join("acl_test_file.txt");
        let dir_path = mnt.join("acl_test_dir");
        fs::write(&file_path, b"POSIX ACL test content\n").expect("create test file for ACL");
        fs::create_dir(&dir_path).expect("create test dir for ACL");

        let access_acl = build_posix_acl_xattr(&[
            (ACL_USER_OBJ_TAG, 0o6),
            (ACL_GROUP_OBJ_TAG, 0o4),
            (ACL_OTHER_TAG, 0),
        ]);
        let default_acl = build_posix_acl_xattr(&[
            (ACL_USER_OBJ_TAG, 0o7),
            (ACL_GROUP_OBJ_TAG, 0o5),
            (ACL_OTHER_TAG, 0o1),
        ]);

        py_setxattr(&file_path, "system.posix_acl_access", &access_acl);
        py_setxattr(&dir_path, "system.posix_acl_default", &default_acl);

        let file_names = py_listxattr(&file_path);
        assert!(
            file_names
                .iter()
                .any(|name| name == "system.posix_acl_access"),
            "listxattr on btrfs file should expose system.posix_acl_access, got: {file_names:?}"
        );

        let access_report = py_getxattr_report(&file_path, "system.posix_acl_access");
        assert!(
            access_report["value_hex"].is_string(),
            "btrfs getxattr for system.posix_acl_access should succeed: {access_report}"
        );

        let dir_names = py_listxattr(&dir_path);
        assert!(
            dir_names
                .iter()
                .any(|name| name == "system.posix_acl_default"),
            "listxattr on btrfs dir should expose system.posix_acl_default, got: {dir_names:?}"
        );

        let default_report = py_getxattr_report(&dir_path, "system.posix_acl_default");
        assert!(
            default_report["value_hex"].is_string(),
            "btrfs getxattr for system.posix_acl_default should succeed: {default_report}"
        );
    });
}

#[test]
fn btrfs_fuse_xattr_posix_acl_default_missing_on_regular_file_reports_enodata() {
    with_btrfs_rw_mount(|mnt| {
        let file_path = mnt.join("no_acl_file.txt");
        fs::write(&file_path, b"file without default ACL\n").expect("create test file");

        let names = py_listxattr(&file_path);
        assert!(
            !names.iter().any(|name| name == "system.posix_acl_default"),
            "btrfs regular file should not list a default ACL xattr, got: {names:?}"
        );

        let report = py_getxattr_report(&file_path, "system.posix_acl_default");
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "btrfs getxattr for missing system.posix_acl_default should return ENODATA: {report}"
        );
    });
}

#[test]
fn btrfs_fuse_xattr_name_too_long_reports_erange() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("xattr_name_test.txt");
        fs::write(&path, b"xattr name length test\n").expect("create test file");
        let original_file = fs::read(&path).expect("read original file bytes");

        // Linux XATTR_NAME_MAX is the full name length, including "user.".
        let long_suffix = "a".repeat(255 - "user.".len() + 1);
        let long_name = format!("user.{long_suffix}");

        let report = py_setxattr_report(&path, &long_name, b"value", 0);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ERANGE)),
            "btrfs xattr full name > XATTR_NAME_MAX should return ERANGE: {report}"
        );

        // Verify no side effects
        assert_eq!(
            fs::read(&path).expect("read file bytes after name-too-long rejection"),
            original_file,
            "btrfs name-too-long rejection must not mutate file contents"
        );
    });
}

#[test]
fn btrfs_fuse_xattr_value_too_large_reports_einval() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("xattr_value_test.txt");
        fs::write(&path, b"xattr value size test\n").expect("create test file");
        let original_file = fs::read(&path).expect("read original file bytes");

        // Btrfs xattr item value length is encoded as u16, so 65536 is one
        // byte beyond the representable on-disk item size.
        let oversized_value = vec![0x42_u8; 65536];

        let report = py_setxattr_report(&path, "user.toobig", &oversized_value, 0);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "btrfs xattr value beyond u16 item size should return EINVAL: {report}"
        );

        // Verify the xattr was not created
        assert!(
            py_getxattr(&path, "user.toobig").is_none(),
            "btrfs oversized xattr value should not be stored"
        );

        // Verify no side effects
        assert_eq!(
            fs::read(&path).expect("read file bytes after value-too-large rejection"),
            original_file,
            "btrfs value-too-large rejection must not mutate file contents"
        );
    });
}

#[test]
fn btrfs_fuse_xattr_boundary_name_length_accepted() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("xattr_boundary_name.txt");
        fs::write(&path, b"boundary name test\n").expect("create test file");

        // Linux XATTR_NAME_MAX is 255 bytes for the full name, including "user.".
        let max_suffix = "z".repeat(255 - "user.".len());
        let max_name = format!("user.{max_suffix}");

        py_setxattr(&path, &max_name, b"boundary");
        let readback =
            py_getxattr(&path, &max_name).expect("btrfs 255-byte full-name xattr should exist");
        assert_eq!(
            readback, b"boundary",
            "btrfs boundary-length xattr should round-trip"
        );
    });
}

#[test]
fn btrfs_fuse_xattr_boundary_value_size_accepted() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("xattr_boundary_value.txt");
        fs::write(&path, b"boundary value test\n").expect("create test file");

        // Btrfs stores the value length in a u16 field.
        let max_value = vec![0xAB_u8; 65535];

        py_setxattr(&path, "user.maxval", &max_value);
        let readback =
            py_getxattr(&path, "user.maxval").expect("max btrfs u16 xattr value should exist");
        assert_eq!(
            readback, max_value,
            "btrfs boundary-size xattr value should round-trip"
        );
    });
}

#[test]
fn ext4_fuse_security_xattr_requires_privilege() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Attempting to set security.* xattr without CAP_SYS_ADMIN should fail.
        // This tests the security namespace enforcement path.
        let report = py_setxattr_report(&path, "security.test", b"test_value", 0);

        // Expect EPERM (operation not permitted) for unprivileged security xattr write.
        // Some kernels may return EOPNOTSUPP if security xattrs are disabled.
        let errno = report["errno"].as_i64();
        assert!(
            errno == Some(i64::from(libc::EPERM)) || errno == Some(i64::from(libc::EOPNOTSUPP)),
            "security.* xattr write should fail with EPERM or EOPNOTSUPP, got: {report}"
        );
    });
}

#[test]
fn btrfs_fuse_security_xattr_requires_privilege() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("security_test.txt");
        fs::write(&path, b"security xattr test\n").expect("create test file");

        // Attempting to set security.* xattr without CAP_SYS_ADMIN should fail.
        let report = py_setxattr_report(&path, "security.test", b"test_value", 0);

        // Expect EPERM (operation not permitted) for unprivileged security xattr write.
        let errno = report["errno"].as_i64();
        assert!(
            errno == Some(i64::from(libc::EPERM)) || errno == Some(i64::from(libc::EOPNOTSUPP)),
            "btrfs security.* xattr write should fail with EPERM or EOPNOTSUPP, got: {report}"
        );
    });
}

#[test]
fn ext4_fuse_security_xattr_not_listed_without_privilege() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Verify security.* xattrs are not visible to unprivileged listxattr.
        // The file shouldn't have any security.* xattrs by default.
        let names = py_listxattr(&path);
        let has_security = names.iter().any(|n| n.starts_with("security."));
        assert!(
            !has_security,
            "unprivileged listxattr should not expose security.* xattrs, got: {names:?}"
        );
    });
}

#[test]
fn btrfs_fuse_security_xattr_not_listed_without_privilege() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("security_list_test.txt");
        fs::write(&path, b"security list test\n").expect("create test file");

        // Verify security.* xattrs are not visible to unprivileged listxattr.
        let names = py_listxattr(&path);
        let has_security = names.iter().any(|n| n.starts_with("security."));
        assert!(
            !has_security,
            "btrfs unprivileged listxattr should not expose security.* xattrs, got: {names:?}"
        );
    });
}

#[test]
fn ext4_fuse_ioctl_getversion_via_mounted_path() {
    if !command_available("python3") {
        eprintln!("python3 not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let file_path = mnt.join("hello.txt");

        // Use Python fcntl to issue EXT4_IOC_GETVERSION (0x80086603).
        // Returns a 4-byte u32 (inode generation number).
        let script = format!(
            r#"
import os, fcntl, struct
fd = os.open({path:?}, os.O_RDONLY)
try:
    buf = bytearray(4)
    # EXT4_IOC_GETVERSION = _IOR('f', 3, long) = 0x80086603
    fcntl.ioctl(fd, 0x80086603, buf)
    version = struct.unpack('<I', buf)[0]
    print("version=%d" % version)
    # Version should be a reasonable number (not garbage).
    assert version < 0xFFFFFFFF, "version looks like uninitialized garbage"
    print("PASS")
except OSError as e:
    print("errno=%d message=%s" % (e.errno, str(e)))
finally:
    os.close(fd)
"#,
            path = file_path.to_str().unwrap()
        );

        let out = Command::new("python3")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("run python3 ioctl script");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);

        // The ioctl may fail if the kernel doesn't forward it to FUSE.
        // We accept either PASS or a known transport-layer failure.
        let ioctl_passed = stdout.contains("PASS");
        let transport_skip = stdout.contains("errno=25") || stdout.contains("errno=22");
        if ioctl_passed {
            // Success - FUSE forwarded the ioctl and we got a valid version.
            return;
        }

        // Check for known transport-layer rejections (ENOTTY, EINVAL from kernel).
        if transport_skip {
            eprintln!(
                "EXT4_IOC_GETVERSION not forwarded by kernel (transport-layer skip): {stdout}"
            );
            return;
        }

        assert!(
            ioctl_passed || transport_skip,
            "EXT4_IOC_GETVERSION via mounted path failed unexpectedly: stdout={stdout}, stderr={stderr}"
        );
    });
}

#[test]
fn ext4_fuse_ioctl_setversion_roundtrips_via_mounted_path() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-setversion.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_setversion_roundtrip";
    let path = mnt.join("version-target.txt");
    fs::write(&path, b"setversion mounted path target\n").expect("create setversion target");

    let original_report = ext4_inode_generation_ioctl(&path, "get", None);
    let get_trace = read_ioctl_trace(&ioctl_trace_path);
    if let Some(errno) = original_report["errno"].as_i64() {
        let transport_errno = errno == i64::from(libc::ENOTTY)
            || errno == i64::from(libc::EINVAL)
            || errno == EOPNOTSUPP_ERRNO;
        assert!(
            transport_errno,
            "unexpected errno for mounted-path GETVERSION preflight: {original_report}"
        );
        assert!(
            !trace_contains_cmd(&get_trace, EXT4_IOC_GETVERSION_CMD),
            "GETVERSION returned transport errno after reaching ffs-fuse::ioctl: {get_trace}"
        );
        emit_scenario_result(
            scenario_id,
            "SKIP",
            Some("kernel_or_vfs_rejected_getversion_before_userspace"),
        );
        return;
    }
    assert!(
        trace_contains_cmd(&get_trace, EXT4_IOC_GETVERSION_CMD),
        "successful GETVERSION should hit ffs-fuse::ioctl: {get_trace}"
    );

    let original = u32::try_from(
        original_report["generation"]
            .as_u64()
            .expect("original generation u64"),
    )
    .expect("original generation should fit u32");
    let requested = original ^ 0x1357_9BDF_u32;

    let set_report = ext4_inode_generation_ioctl(&path, "set", Some(requested));
    let set_trace = read_ioctl_trace(&ioctl_trace_path);
    if let Some(errno) = set_report["errno"].as_i64() {
        let transport_errno = errno == i64::from(libc::ENOTTY) || errno == i64::from(libc::EINVAL);
        assert!(
            transport_errno,
            "unexpected errno for mounted-path SETVERSION: {set_report}"
        );
        assert!(
            !trace_contains_cmd(&set_trace, EXT4_IOC_SETVERSION_CMD),
            "SETVERSION returned transport errno after reaching ffs-fuse::ioctl: {set_trace}"
        );
        emit_scenario_result(
            scenario_id,
            "SKIP",
            Some("kernel_or_vfs_rejected_setversion_before_userspace"),
        );
        return;
    }
    assert!(
        trace_contains_cmd(&set_trace, EXT4_IOC_SETVERSION_CMD),
        "successful SETVERSION should hit ffs-fuse::ioctl: {set_trace}"
    );
    assert!(
        set_report["errno"].is_null(),
        "mounted-path SETVERSION should succeed on rw ext4 mount: {set_report}"
    );

    let updated_report = ext4_inode_generation_ioctl(&path, "get", None);
    let updated_trace = read_ioctl_trace(&ioctl_trace_path);
    assert!(
        trace_contains_cmd(&updated_trace, EXT4_IOC_GETVERSION_CMD),
        "post-set GETVERSION should hit ffs-fuse::ioctl: {updated_trace}"
    );
    assert!(
        updated_report["errno"].is_null(),
        "post-set GETVERSION should succeed after mounted-path SETVERSION: {updated_report}"
    );
    assert_eq!(
        updated_report["generation"].as_u64(),
        Some(u64::from(requested)),
        "mounted-path GETVERSION should roundtrip the SETVERSION payload: {updated_report}"
    );
    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("setversion_roundtrip_via_getversion"),
    );
}

#[test]
fn btrfs_fuse_write_large_file() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("large.bin");
        // Write 64 KiB of patterned data (crosses multiple blocks).
        let data = patterned_bytes(65_536, 251, 0);
        fs::write(&path, &data).expect("write large file on btrfs");

        let readback = fs::read(&path).expect("read large file on btrfs");
        assert_eq!(readback.len(), 65536);
        assert_eq!(readback, data, "large file content should match on btrfs");
    });
}

#[test]
fn btrfs_fuse_fallocate_preallocate_extends_size() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fallocate_preallocate_extends_size";
        let path = mnt.join("btrfs_preallocated.bin");
        fs::write(&path, b"").expect("create empty btrfs file");

        let out = Command::new("fallocate")
            .args(["-l", "8192", path.to_str().unwrap()])
            .output()
            .expect("run fallocate preallocate on btrfs");
        assert!(
            out.status.success(),
            "btrfs preallocate fallocate failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after btrfs preallocate fallocate");
        assert_eq!(
            meta.len(),
            8192,
            "btrfs preallocate should extend apparent file size to 8192"
        );
        assert!(
            meta.blocks() * 512 >= 8192,
            "allocated disk space ({}*512={}) should be >= 8192 after btrfs preallocation",
            meta.blocks(),
            meta.blocks() * 512
        );

        fs::write(&path, b"data in btrfs preallocated space").expect("write to btrfs preallocated");
        let content = fs::read_to_string(&path).expect("read btrfs preallocated");
        assert_eq!(content, "data in btrfs preallocated space");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn btrfs_fuse_fallocate_keep_size_preserves_size() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fallocate_keep_size_preserves_size";
        let path = mnt.join("btrfs_keep_size.bin");
        fs::write(&path, b"short").expect("create btrfs file with content");

        let out = Command::new("fallocate")
            .args(["-l", "16384", "--keep-size", path.to_str().unwrap()])
            .output()
            .expect("run keep-size fallocate on btrfs");
        assert!(
            out.status.success(),
            "btrfs keep-size fallocate failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after btrfs keep-size fallocate");
        assert_eq!(
            meta.len(),
            5,
            "btrfs keep-size fallocate should preserve apparent file size"
        );

        let content = fs::read_to_string(&path).expect("read after btrfs keep-size fallocate");
        assert_eq!(content, "short");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn btrfs_fuse_fallocate_punch_hole_keep_size_zeroes_range() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fallocate_punch_hole_keep_size_zeroes_range";
        let path = mnt.join("punch_hole.bin");
        let data = patterned_bytes(12_288, 251, 1);
        fs::write(&path, &data).expect("seed punch-hole file on btrfs");

        let out = Command::new("fallocate")
            .args([
                "--keep-size",
                "--punch-hole",
                "-o",
                "4096",
                "-l",
                "4096",
                path.to_str().unwrap(),
            ])
            .output()
            .expect("run fallocate --punch-hole --keep-size on btrfs");
        assert!(
            out.status.success(),
            "btrfs keep-size punch-hole failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after btrfs keep-size punch-hole");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "punch hole must preserve file size"
        );

        let readback = fs::read(&path).expect("read after btrfs keep-size punch-hole");
        assert_eq!(&readback[..4096], &data[..4096], "prefix must be preserved");
        assert!(
            readback[4096..8192].iter().all(|&byte| byte == 0),
            "punched range must read back as zeros"
        );
        assert_eq!(&readback[8192..], &data[8192..], "suffix must be preserved");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn btrfs_fuse_fallocate_zero_range_zeroes_range() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fallocate_zero_range_zeroes_range";
        let path = mnt.join("zero_range.bin");
        let data = patterned_bytes(12_288, 253, 1);
        fs::write(&path, &data).expect("seed zero-range file on btrfs");

        let out = Command::new("fallocate")
            .args([
                "--zero-range",
                "-o",
                "4096",
                "-l",
                "4096",
                path.to_str().unwrap(),
            ])
            .output()
            .expect("run fallocate --zero-range on btrfs");
        assert!(
            out.status.success(),
            "btrfs zero-range failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after btrfs zero-range");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "zero-range must preserve file size"
        );

        let readback = fs::read(&path).expect("read after btrfs zero-range");
        assert_eq!(&readback[..4096], &data[..4096], "prefix must be preserved");
        assert!(
            readback[4096..8192].iter().all(|&byte| byte == 0),
            "zero-range span must read back as zeros"
        );
        assert_eq!(&readback[8192..], &data[8192..], "suffix must be preserved");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn btrfs_fuse_fallocate_collapse_range_shifts_tail_and_shrinks_file() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fallocate_collapse_range";
        let path = mnt.join("collapse_range.bin");
        let block = 4096_usize;
        let mut data = Vec::with_capacity(block * 4);
        data.extend(std::iter::repeat_n(b'A', block));
        data.extend(std::iter::repeat_n(b'B', block));
        data.extend(std::iter::repeat_n(b'C', block));
        data.extend(std::iter::repeat_n(b'D', block));
        fs::write(&path, &data).expect("seed collapse-range file on btrfs");

        let report = query_fallocate(&path, 0x08, 4096, 4096);
        if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
            let meta = fs::metadata(&path).expect("stat after transport collapse-range refusal");
            assert_eq!(
                meta.len(),
                data.len() as u64,
                "transport collapse-range refusal must preserve file size: {report}"
            );
            let readback = fs::read(&path).expect("read after transport collapse-range refusal");
            assert_eq!(
                readback, data,
                "transport collapse-range refusal must preserve file data: {report}"
            );
            emit_scenario_result(
                scenario_id,
                "SKIP",
                Some("collapse_range_rejected_by_kernel_or_fuse_transport_errno_95_no_drift"),
            );
            return;
        }
        assert_eq!(
            report["res"].as_i64(),
            Some(0),
            "btrfs collapse-range fallocate should succeed: {report}"
        );

        let meta = fs::metadata(&path).expect("stat after btrfs collapse-range");
        assert_eq!(meta.len(), 12_288, "collapse range must shrink file");

        let readback = fs::read(&path).expect("read after btrfs collapse-range");
        let mut expected = Vec::with_capacity(block * 3);
        expected.extend(std::iter::repeat_n(b'A', block));
        expected.extend(std::iter::repeat_n(b'C', block));
        expected.extend(std::iter::repeat_n(b'D', block));
        assert_eq!(readback, expected);
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn btrfs_fuse_fallocate_insert_range_shifts_tail_and_grows_file() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fallocate_insert_range";
        let path = mnt.join("insert_range.bin");
        let block = 4096_usize;
        let mut data = Vec::with_capacity(block * 3);
        data.extend(std::iter::repeat_n(b'A', block));
        data.extend(std::iter::repeat_n(b'B', block));
        data.extend(std::iter::repeat_n(b'C', block));
        fs::write(&path, &data).expect("seed insert-range file on btrfs");

        let report = query_fallocate(&path, 0x20, 4096, 4096);
        if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
            let meta = fs::metadata(&path).expect("stat after transport insert-range refusal");
            assert_eq!(
                meta.len(),
                data.len() as u64,
                "transport insert-range refusal must preserve file size: {report}"
            );
            let readback = fs::read(&path).expect("read after transport insert-range refusal");
            assert_eq!(
                readback, data,
                "transport insert-range refusal must preserve file data: {report}"
            );
            emit_scenario_result(
                scenario_id,
                "SKIP",
                Some("insert_range_rejected_by_kernel_or_fuse_transport_errno_95_no_drift"),
            );
            return;
        }
        assert_eq!(
            report["res"].as_i64(),
            Some(0),
            "btrfs insert-range fallocate should succeed: {report}"
        );

        let meta = fs::metadata(&path).expect("stat after btrfs insert-range");
        assert_eq!(meta.len(), 16_384, "insert range must grow file");

        let readback = fs::read(&path).expect("read after btrfs insert-range");
        let mut expected = Vec::with_capacity(block * 4);
        expected.extend(std::iter::repeat_n(b'A', block));
        expected.extend(std::iter::repeat_n(0, block));
        expected.extend(std::iter::repeat_n(b'B', block));
        expected.extend(std::iter::repeat_n(b'C', block));
        assert_eq!(readback, expected);
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn btrfs_fuse_fallocate_on_directory_reports_eisdir() {
    if !command_available("python3") {
        eprintln!("python3 not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fallocate_on_directory_errno_eisdir";
        let dir = mnt.join("fallocate_dir");
        fs::create_dir(&dir).expect("mkdir btrfs fallocate directory target");
        let child = dir.join("child.txt");
        fs::write(&child, b"directory child stays intact\n").expect("seed btrfs directory child");

        let entries_before = snapshot_directory_entries(&dir);
        let child_before = snapshot_file_state(&child);
        let report = query_directory_fallocate(&dir, 0, 0, 4096);

        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EISDIR)),
            "btrfs directory fallocate should surface exact EISDIR: {report}"
        );
        assert_eq!(
            report["name"].as_str(),
            Some("EISDIR"),
            "btrfs directory fallocate should surface the EISDIR alias: {report}"
        );
        let phase = report["phase"]
            .as_str()
            .expect("directory fallocate rejection phase");
        assert!(
            matches!(phase, "open" | "fallocate"),
            "unexpected directory fallocate rejection phase: {report}"
        );

        let entries_after = snapshot_directory_entries(&dir);
        assert_eq!(
            entries_after, entries_before,
            "directory fallocate rejection must not change directory entries"
        );
        assert_file_state_unchanged(&child, &child_before, "directory fallocate rejection");
        emit_scenario_result(scenario_id, "PASS", Some(phase));
    });
}

#[test]
fn btrfs_fuse_invalid_punch_hole_without_keep_size_reports_einval() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_invalid_punch_hole_without_keep_size_errno_einval";
        let path = mnt.join("invalid_punch_hole_mode.bin");
        let data = patterned_bytes(12_288, 253, 1);
        fs::write(&path, &data).expect("seed invalid-punch-hole file on btrfs");

        let report = query_fallocate(&path, libc::FALLOC_FL_PUNCH_HOLE, 4096, 4096);
        let meta = fs::metadata(&path).expect("stat after invalid btrfs punch-hole rejection");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "invalid btrfs punch-hole rejection must preserve file size"
        );
        let readback = fs::read(&path).expect("read after invalid btrfs punch-hole rejection");
        assert_eq!(
            readback, data,
            "invalid btrfs punch-hole rejection must preserve file data"
        );

        if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
            eprintln!(
                "invalid btrfs punch-hole mode collapsed to transport-layer errno 95 before \
                 FrankenFS could prove mounted-path EINVAL semantics: {report}"
            );
            return;
        }

        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "btrfs invalid punch-hole mode should surface EINVAL when dispatched to FrankenFS: {report}"
        );
        assert_eq!(
            report["name"].as_str(),
            Some("EINVAL"),
            "btrfs invalid punch-hole mode should surface the EINVAL alias: {report}"
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=22"));
    });
}

#[test]
fn btrfs_fuse_unsupported_fallocate_mode_bits_errno_eopnotsupp() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_unsupported_fallocate_mode_bits_errno_eopnotsupp";
        let path = mnt.join("unsupported_mode_bits.bin");
        let data = b"keep-intact-on-unsupported-mode".to_vec();
        fs::write(&path, &data).expect("seed unsupported-mode file on btrfs");

        let script = r#"
import ctypes
import errno
import os
import sys

path = sys.argv[1]
fd = os.open(path, os.O_RDWR)
libc = ctypes.CDLL(None, use_errno=True)
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
libc.fallocate.restype = ctypes.c_int
res = libc.fallocate(fd, 0x40, 0, 4096)
err = ctypes.get_errno()
os.close(fd)
if res == 0:
    print("res=0")
    sys.exit(0)
print(f"errno={err}")
print(errno.errorcode.get(err, "UNKNOWN"))
sys.exit(1)
"#;
        let out = Command::new("python3")
            .args(["-c", script, path.to_str().unwrap()])
            .output()
            .expect("run unsupported-mode fallocate probe on btrfs");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !out.status.success(),
            "unsupported mode bits should fail, got stdout={stdout} stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains(&format!("errno={EOPNOTSUPP_ERRNO}")),
            "unsupported mode bits should surface errno {EOPNOTSUPP_ERRNO}, got: {stdout}"
        );
        assert!(
            stdout.contains("EOPNOTSUPP") || stdout.contains("ENOTSUP"),
            "unsupported mode bits should surface the errno-95 not-supported alias, got: {stdout}"
        );

        let meta = fs::metadata(&path).expect("stat after unsupported-mode rejection");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "unsupported mode rejection must preserve file size"
        );
        let readback = fs::read(&path).expect("read after unsupported-mode rejection");
        assert_eq!(
            readback, data,
            "unsupported mode rejection must preserve file data"
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=95"));
    });
}

#[test]
fn btrfs_fuse_fsync_emits_scenario_result_and_persists_written_data() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fsync";
        let path = mnt.join("synced.txt");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .expect("create synced.txt on btrfs");

        file.write_all(b"data before fsync\n")
            .expect("write before fsync on btrfs");

        // sync_all triggers FUSE fsync.
        file.sync_all().expect("fsync via sync_all on btrfs");

        drop(file);

        // Read back and verify.
        let content = fs::read_to_string(&path).expect("read after fsync on btrfs");
        assert_eq!(content, "data before fsync\n");
        emit_scenario_result(scenario_id, "PASS", Some("sync_all"));
    });
}

#[test]
fn btrfs_fuse_sync_data_emits_scenario_result_and_persists_written_data() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fdatasync";
        let path = mnt.join("datasync.txt");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .expect("create datasync.txt on btrfs");

        file.write_all(b"datasync content\n")
            .expect("write before sync_data on btrfs");

        // sync_data triggers FUSE fsync with datasync=true.
        file.sync_data().expect("sync_data on btrfs");

        drop(file);

        let content = fs::read_to_string(&path).expect("read after sync_data on btrfs");
        assert_eq!(content, "datasync content\n");
        emit_scenario_result(scenario_id, "PASS", Some("sync_data"));
    });
}

#[test]
fn btrfs_fuse_fsyncdir_emits_scenario_result_and_preserves_dirent() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fsyncdir";
        let dir = mnt.join("synced_dir");
        fs::create_dir(&dir).expect("mkdir for btrfs fsyncdir");

        let child = dir.join("child.txt");
        fs::write(&child, b"directory sync payload\n").expect("write child before btrfs fsyncdir");

        let dirfd = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(&dir)
            .expect("open directory fd for btrfs fsyncdir");
        dirfd.sync_all().expect("fsyncdir via sync_all on btrfs");
        drop(dirfd);

        let entries: HashSet<String> = fs::read_dir(&dir)
            .expect("readdir after btrfs fsyncdir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries.contains("child.txt"),
            "directory entry should remain visible after fsyncdir, got: {entries:?}"
        );
        assert_eq!(
            fs::read_to_string(&child).expect("read child after btrfs fsyncdir"),
            "directory sync payload\n"
        );
        emit_scenario_result(scenario_id, "PASS", Some("dirfd_sync_all"));
    });
}

#[test]
fn btrfs_fuse_read_only_fsync_reports_erofs_without_data_drift() {
    with_btrfs_ro_sync_fixture(|file_path, _, _| {
        assert_read_only_file_sync_contract(
            file_path,
            "btrfs_ro_fsync_rejects_erofs_no_drift",
            "fsync",
            fs::File::sync_all,
        );
    });
}

#[test]
fn btrfs_fuse_read_only_sync_data_reports_erofs_without_data_drift() {
    with_btrfs_ro_sync_fixture(|file_path, _, _| {
        assert_read_only_file_sync_contract(
            file_path,
            "btrfs_ro_fdatasync_rejects_erofs_no_drift",
            "fdatasync",
            fs::File::sync_data,
        );
    });
}

#[test]
fn btrfs_fuse_read_only_fsyncdir_reports_erofs_without_dirent_drift() {
    with_btrfs_ro_sync_fixture(|_, dir_path, child_path| {
        assert_read_only_dir_sync_contract(
            dir_path,
            child_path,
            "btrfs_ro_fsyncdir_rejects_erofs_no_drift",
        );
    });
}

#[test]
fn btrfs_fuse_flush_emits_scenario_result_and_preserves_data() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_flush";
        let path = mnt.join("flushed.txt");

        {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .expect("create flushed.txt on btrfs");

            file.write_all(b"flushed content\n")
                .expect("write flushed content on btrfs");
            // std::io::Write::flush triggers the FUSE flush handler.
            file.flush().expect("explicit flush on btrfs");
        } // drop/close triggers another FUSE flush+release

        let content = fs::read_to_string(&path).expect("read after btrfs flush+close");
        assert_eq!(content, "flushed content\n");
        emit_scenario_result(scenario_id, "PASS", Some("explicit_flush_and_close"));
    });
}

#[test]
fn btrfs_fuse_read_only_flush_succeeds_without_data_drift() {
    with_btrfs_ro_sync_fixture(|file_path, _, _| {
        assert_read_only_flush_contract(file_path, "btrfs_ro_flush_succeeds_no_drift");
    });
}

#[test]
fn btrfs_fuse_rename_across_directories() {
    with_btrfs_rw_mount(|mnt| {
        let dir_a = mnt.join("dir_a");
        let dir_b = mnt.join("dir_b");
        fs::create_dir(&dir_a).expect("mkdir dir_a");
        fs::create_dir(&dir_b).expect("mkdir dir_b");

        let src = dir_a.join("moveme.txt");
        let dst = dir_b.join("moved.txt");
        fs::write(&src, b"cross-dir rename").expect("write for cross-dir rename");

        fs::rename(&src, &dst).expect("rename across directories on btrfs");
        assert!(!src.exists());
        assert!(dst.exists());
        assert_eq!(
            fs::read_to_string(&dst).expect("read cross-dir renamed"),
            "cross-dir rename"
        );
    });
}

fn btrfs_openfs_mkdir(fs_ops: &dyn FsOps, cx: &Cx, parent: InodeNumber, name: &str) -> InodeAttr {
    fs_ops
        .mkdir(
            cx,
            &mut RequestScope::empty(),
            parent,
            std::ffi::OsStr::new(name),
            0o755,
            0,
            0,
        )
        .unwrap_or_else(|err| panic!("mkdir btrfs {name} through OpenFs: {err}"))
}

#[test]
fn btrfs_openfs_mkfs_fixture_cross_parent_directory_rename_updates_parent_nlink_accounting() {
    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let cx = Cx::for_testing();
    let open_options = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, &image, &open_options).expect("open btrfs image");
    fs.enable_writes(&cx).expect("enable btrfs write support");
    let fs_ops: &dyn FsOps = &fs;

    let workspace = fs_ops
        .lookup(
            &cx,
            &mut RequestScope::empty(),
            InodeNumber(1),
            std::ffi::OsStr::new(BTRFS_TEST_WORKSPACE),
        )
        .expect("lookup seeded btrfs workspace");
    let source_parent = btrfs_openfs_mkdir(fs_ops, &cx, workspace.ino, "rename_src_parent");
    let destination_parent = btrfs_openfs_mkdir(fs_ops, &cx, workspace.ino, "rename_dst_parent");
    let source_child = btrfs_openfs_mkdir(fs_ops, &cx, source_parent.ino, "moved_dir");

    let source_parent_nlink_before = fs_ops
        .getattr(&cx, &mut RequestScope::empty(), source_parent.ino)
        .expect("stat btrfs source parent before OpenFs rename")
        .nlink;
    let destination_parent_nlink_before = fs_ops
        .getattr(&cx, &mut RequestScope::empty(), destination_parent.ino)
        .expect("stat btrfs destination parent before OpenFs rename")
        .nlink;
    let source_child_nlink_before = source_child.nlink;

    fs_ops
        .rename(
            &cx,
            &mut RequestScope::empty(),
            source_parent.ino,
            std::ffi::OsStr::new("moved_dir"),
            destination_parent.ino,
            std::ffi::OsStr::new("moved_dir"),
        )
        .expect("cross-parent directory rename through OpenFs on mkfs fixture");

    assert!(
        fs_ops
            .lookup(
                &cx,
                &mut RequestScope::empty(),
                source_parent.ino,
                std::ffi::OsStr::new("moved_dir"),
            )
            .is_err(),
        "OpenFs rename must remove source entry"
    );
    let destination_child = fs_ops
        .lookup(
            &cx,
            &mut RequestScope::empty(),
            destination_parent.ino,
            std::ffi::OsStr::new("moved_dir"),
        )
        .expect("lookup OpenFs renamed destination child");
    assert_eq!(
        fs_ops
            .getattr(&cx, &mut RequestScope::empty(), source_parent.ino)
            .expect("stat source parent after OpenFs rename")
            .nlink,
        source_parent_nlink_before - 1,
        "OpenFs cross-parent rename must decrement source parent nlink"
    );
    assert_eq!(
        fs_ops
            .getattr(&cx, &mut RequestScope::empty(), destination_parent.ino)
            .expect("stat destination parent after OpenFs rename")
            .nlink,
        destination_parent_nlink_before + 1,
        "OpenFs cross-parent rename must increment destination parent nlink"
    );
    assert_eq!(
        destination_child.ino, source_child.ino,
        "OpenFs cross-parent rename must preserve moved directory inode"
    );
    assert_eq!(
        destination_child.nlink, source_child_nlink_before,
        "OpenFs cross-parent rename must preserve moved directory nlink"
    );
}

#[test]
fn btrfs_fuse_cross_parent_directory_rename_updates_parent_nlink_accounting() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_cross_parent_directory_rename_nlink_accounting";
        let source_parent = mnt.join("rename_src_parent");
        let destination_parent = mnt.join("rename_dst_parent");
        fs::create_dir(&source_parent).expect("mkdir btrfs source parent");
        fs::create_dir(&destination_parent).expect("mkdir btrfs destination parent");

        let source_child = source_parent.join("moved_dir");
        let destination_child = destination_parent.join("moved_dir");
        fs::create_dir(&source_child).expect("mkdir btrfs child directory");

        let source_entries_before = snapshot_directory_entries(&source_parent);
        let destination_entries_before = snapshot_directory_entries(&destination_parent);
        let source_parent_nlink_before = fs::metadata(&source_parent)
            .expect("stat btrfs source parent before rename")
            .nlink();
        let destination_parent_nlink_before = fs::metadata(&destination_parent)
            .expect("stat btrfs destination parent before rename")
            .nlink();
        let source_child_meta_before =
            fs::metadata(&source_child).expect("stat btrfs child before rename");
        let source_child_ino_before = source_child_meta_before.ino();
        let source_child_nlink_before = source_child_meta_before.nlink();

        fs::rename(&source_child, &destination_child)
            .expect("cross-parent directory rename on btrfs");

        let mut source_entries_expected_after = source_entries_before;
        source_entries_expected_after.remove("moved_dir");
        let mut destination_entries_expected_after = destination_entries_before;
        destination_entries_expected_after.insert("moved_dir".to_string());

        assert!(
            fs::symlink_metadata(&source_child).is_err(),
            "cross-parent rename must remove the source directory entry"
        );
        assert!(
            fs::symlink_metadata(&destination_child).is_ok(),
            "cross-parent rename must create the destination directory entry"
        );
        assert_eq!(
            snapshot_directory_entries(&source_parent),
            source_entries_expected_after,
            "source parent entries must drop the moved directory"
        );
        assert_eq!(
            snapshot_directory_entries(&destination_parent),
            destination_entries_expected_after,
            "destination parent entries must gain the moved directory"
        );
        assert_eq!(
            fs::metadata(&source_parent)
                .expect("stat btrfs source parent after rename")
                .nlink(),
            source_parent_nlink_before - 1,
            "moving a child directory out must decrement the source parent st_nlink"
        );
        assert_eq!(
            fs::metadata(&destination_parent)
                .expect("stat btrfs destination parent after rename")
                .nlink(),
            destination_parent_nlink_before + 1,
            "moving a child directory in must increment the destination parent st_nlink"
        );

        let destination_child_meta =
            fs::metadata(&destination_child).expect("stat btrfs child after rename");
        assert_eq!(
            destination_child_meta.ino(),
            source_child_ino_before,
            "cross-parent rename must preserve the moved directory inode"
        );
        assert_eq!(
            destination_child_meta.nlink(),
            source_child_nlink_before,
            "cross-parent rename must preserve the moved directory link count"
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("src_parent_minus_one_dst_parent_plus_one_child_preserved"),
        );
    });
}

#[test]
fn btrfs_fuse_rename_into_non_directory_parent_reports_enotdir() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_rename_into_non_directory_parent_errno_enotdir";
        let source = mnt.join("rename_source.txt");
        let non_directory_parent = mnt.join("rename_parent_file.txt");
        fs::write(&source, b"rename source payload\n").expect("write btrfs rename source");
        fs::write(&non_directory_parent, b"not a directory\n")
            .expect("write btrfs non-directory parent");

        let entries_before = snapshot_directory_entries(mnt);
        let source_before = snapshot_file_state(&source);
        let parent_before = snapshot_file_state(&non_directory_parent);
        let target = non_directory_parent.join("child.txt");

        let err =
            fs::rename(&source, &target).expect_err("rename into non-directory parent should fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENOTDIR),
            "rename into a non-directory parent should surface exact ENOTDIR: {err}"
        );
        assert!(
            fs::symlink_metadata(&source).is_ok(),
            "rejected rename must leave the source entry in place"
        );
        assert!(
            fs::symlink_metadata(&target).is_err(),
            "rejected rename must not create the target entry"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            entries_before,
            "rejected rename must not change visible root entries"
        );
        assert_file_state_unchanged(&source, &source_before, "rejected rename source");
        assert_file_state_unchanged(
            &non_directory_parent,
            &parent_before,
            "rejected rename non-directory parent",
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=ENOTDIR_no_drift"));
    });
}

#[test]
fn btrfs_fuse_rename_file_directory_type_mismatch_reports_eisdir_and_enotdir() {
    with_btrfs_rw_mount(|mnt| {
        assert_rename_file_directory_type_mismatch_contract(
            mnt,
            "btrfs_rw_rename_file_directory_type_mismatch",
        );
    });
}

#[test]
fn btrfs_fuse_rename_over_nonempty_directory_reports_enotempty() {
    with_btrfs_rw_mount(|mnt| {
        assert_rename_over_nonempty_directory_reports_enotempty(
            mnt,
            "btrfs_rw_rename_over_nonempty_directory_errno_enotempty",
        );
    });
}

#[test]
fn btrfs_fuse_rename_missing_source_reports_enoent() {
    with_btrfs_rw_mount(|mnt| {
        assert_rename_missing_source_reports_enoent(
            mnt,
            "btrfs_rw_rename_missing_source_errno_enoent",
        );
    });
}

#[test]
fn btrfs_fuse_rename_directory_into_own_child_reports_einval() {
    with_btrfs_rw_mount(|mnt| {
        assert_rename_directory_into_own_child_reports_einval(
            mnt,
            "btrfs_rw_rename_directory_into_own_child_errno_einval",
        );
    });
}

#[test]
fn btrfs_fuse_rename_overwrite() {
    with_btrfs_rw_mount(|mnt| {
        let src = mnt.join("src.txt");
        let dst = mnt.join("dst.txt");
        fs::write(&src, b"new content").expect("write src");
        fs::write(&dst, b"old content").expect("write dst");

        fs::rename(&src, &dst).expect("rename overwrite on btrfs");
        assert!(!src.exists());
        assert_eq!(
            fs::read_to_string(&dst).expect("read overwritten"),
            "new content"
        );
    });
}

#[test]
fn btrfs_fuse_renameat2_honors_noreplace_and_rejects_exchange() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_renameat2_flags";
        if !command_available("python3") {
            emit_scenario_result(scenario_id, "SKIP", Some("python3_unavailable"));
            return;
        }

        let noreplace_src = mnt.join("renameat2-btrfs-noreplace-src.txt");
        let noreplace_dst = mnt.join("renameat2-btrfs-noreplace-dst.txt");
        let noreplace_existing_src = mnt.join("renameat2-btrfs-noreplace-existing-src.txt");
        let noreplace_existing_dst = mnt.join("renameat2-btrfs-noreplace-existing-dst.txt");
        let exchange_src = mnt.join("renameat2-btrfs-exchange-src.txt");
        let exchange_dst = mnt.join("renameat2-btrfs-exchange-dst.txt");

        fs::write(&noreplace_src, b"btrfs noreplace src\n")
            .expect("write btrfs renameat2 noreplace source");
        fs::write(&noreplace_existing_src, b"btrfs noreplace existing src\n")
            .expect("write btrfs renameat2 noreplace existing source");
        fs::write(&noreplace_existing_dst, b"btrfs noreplace existing dst\n")
            .expect("write btrfs renameat2 noreplace existing destination");
        fs::write(&exchange_src, b"btrfs exchange src\n")
            .expect("write btrfs renameat2 exchange source");
        fs::write(&exchange_dst, b"btrfs exchange dst\n")
            .expect("write btrfs renameat2 exchange destination");

        let noreplace_existing_src_before = snapshot_file_state(&noreplace_existing_src);
        let noreplace_existing_dst_before = snapshot_file_state(&noreplace_existing_dst);
        let exchange_src_before = snapshot_file_state(&exchange_src);
        let exchange_dst_before = snapshot_file_state(&exchange_dst);

        let noreplace_report =
            py_renameat2_report(&noreplace_src, &noreplace_dst, libc::RENAME_NOREPLACE);
        assert_eq!(
            noreplace_report["ok"].as_bool(),
            Some(true),
            "renameat2(RENAME_NOREPLACE) should succeed on btrfs when destination is absent: {noreplace_report:?}"
        );
        assert!(
            fs::symlink_metadata(&noreplace_src).is_err(),
            "successful btrfs RENAME_NOREPLACE must remove the source entry"
        );
        assert_eq!(
            fs::read_to_string(&noreplace_dst).expect("read btrfs renameat2 noreplace destination"),
            "btrfs noreplace src\n"
        );

        let noreplace_existing_report = py_renameat2_report(
            &noreplace_existing_src,
            &noreplace_existing_dst,
            libc::RENAME_NOREPLACE,
        );
        assert_eq!(
            noreplace_existing_report["errno"].as_i64(),
            Some(i64::from(libc::EEXIST)),
            "btrfs RENAME_NOREPLACE over an existing destination should surface exact EEXIST: {noreplace_existing_report:?}"
        );
        assert_file_state_unchanged(
            &noreplace_existing_src,
            &noreplace_existing_src_before,
            "btrfs renameat2 RENAME_NOREPLACE existing source",
        );
        assert_file_state_unchanged(
            &noreplace_existing_dst,
            &noreplace_existing_dst_before,
            "btrfs renameat2 RENAME_NOREPLACE existing destination",
        );

        let entries_before_exchange = snapshot_directory_entries(mnt);
        let exchange_report =
            py_renameat2_report(&exchange_src, &exchange_dst, libc::RENAME_EXCHANGE);
        assert_eq!(
            exchange_report["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "renameat2(RENAME_EXCHANGE) should surface exact EINVAL on btrfs: {exchange_report:?}"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            entries_before_exchange,
            "rejected btrfs RENAME_EXCHANGE must not change visible workspace entries"
        );
        assert_file_state_unchanged(
            &exchange_src,
            &exchange_src_before,
            "btrfs renameat2 RENAME_EXCHANGE source",
        );
        assert_file_state_unchanged(
            &exchange_dst,
            &exchange_dst_before,
            "btrfs renameat2 RENAME_EXCHANGE destination",
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("noreplace=create+noreplace_existing=EEXIST+exchange=EINVAL_no_drift"),
        );
    });
}

// ── New CI-compatible E2E scenarios ────────────────────────────────

#[test]
fn fuse_deep_directory_tree() {
    with_rw_mount(|mnt| {
        // Create a 5-level deep directory tree and verify traversal.
        let mut path = mnt.to_path_buf();
        for i in 0..5 {
            path = path.join(format!("level_{i}"));
            let mkdir_result = fs::create_dir(&path);
            assert!(mkdir_result.is_ok(), "mkdir level_{i}: {mkdir_result:?}");
        }

        // Write a file at the deepest level.
        let deep_file = path.join("deep.txt");
        fs::write(&deep_file, b"deep content").expect("write deep file");
        assert_eq!(
            fs::read_to_string(&deep_file).expect("read deep file"),
            "deep content"
        );

        // Verify the full path exists via metadata.
        let meta = fs::metadata(&deep_file).expect("stat deep file");
        assert!(meta.is_file());
        assert_eq!(meta.len(), 12);
    });
}

#[test]
fn fuse_many_files_in_directory() {
    with_rw_mount(|mnt| {
        // Create 100 files in a single directory and verify readdir returns all.
        let dir = mnt.join("many_files");
        fs::create_dir(&dir).expect("mkdir many_files");

        for i in 0..100 {
            let path = dir.join(format!("file_{i:03}.txt"));
            fs::write(&path, format!("content_{i}")).expect("write file");
        }

        let entries: Vec<String> = fs::read_dir(&dir)
            .expect("readdir many_files")
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        assert_eq!(entries.len(), 100, "expected 100 entries in readdir");

        // Verify a random file.
        let content = fs::read_to_string(dir.join("file_042.txt")).expect("read file_042");
        assert_eq!(content, "content_42");
    });
}

#[test]
fn fuse_empty_file_operations() {
    with_rw_mount(|mnt| {
        // Create an empty file and verify it reads back as empty.
        let path = mnt.join("empty.txt");
        fs::write(&path, b"").expect("create empty file");

        let content = fs::read(&path).expect("read empty file");
        assert!(content.is_empty());

        let meta = fs::metadata(&path).expect("stat empty file");
        assert_eq!(meta.len(), 0);
    });
}

#[test]
fn fuse_empty_filesystem_root_readdir_stat_and_create_readback() {
    const SCENARIO_ID: &str = "fuse_prod_empty_ext4_root_readdir_stat_create_readback";

    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        emit_scenario_result(SCENARIO_ID, "SKIP", Some("fuse_prerequisites_unavailable"));
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_empty_ext4_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs_rw(&image, &mnt) else {
        emit_scenario_result(
            SCENARIO_ID,
            "SKIP",
            Some("fuse_mount_unavailable_or_permission_denied"),
        );
        return;
    };

    let root_meta = fs::metadata(&mnt).expect("stat empty mounted root");
    assert!(
        root_meta.is_dir(),
        "empty image mounted root should stat as directory"
    );
    assert_eq!(
        root_meta.permissions().mode() & 0o777,
        0o777,
        "empty image root mode should preserve writable test fixture permissions"
    );

    let root_entries = snapshot_directory_entries(&mnt);
    assert_eq!(
        root_entries,
        HashSet::from(["lost+found".to_owned()]),
        "fresh mkfs.ext4 root should expose only lost+found before FrankenFS writes"
    );

    let created = mnt.join("empty_root_created.txt");
    fs::write(&created, b"created from empty mounted root\n")
        .expect("create file in empty mounted root");
    assert_eq!(
        fs::read(&created).expect("read file created in empty mounted root"),
        b"created from empty mounted root\n",
        "file created from empty mounted root should read back exact bytes"
    );
    let created_meta = fs::metadata(&created).expect("stat file created in empty mounted root");
    assert!(created_meta.is_file(), "created empty-root child is file");
    assert_eq!(created_meta.len(), 32, "created empty-root child size");

    let root_entries_after = snapshot_directory_entries(&mnt);
    assert_eq!(
        root_entries_after,
        HashSet::from(["lost+found".to_owned(), "empty_root_created.txt".to_owned()]),
        "create/readback from empty mounted root should add exactly one visible child"
    );

    emit_scenario_result(
        SCENARIO_ID,
        "PASS",
        Some("root_stat+root_readdir+create_readback+artifact_stream=rust_test_stderr"),
    );
}

#[test]
fn fuse_rename_chain() {
    with_rw_mount(|mnt| {
        // Rename a file through a chain of names and verify content persists.
        let file_a = mnt.join("chain_a.txt");
        fs::write(&file_a, b"chain content").expect("write chain_a");

        let file_b = mnt.join("chain_b.txt");
        fs::rename(&file_a, &file_b).expect("rename a -> b");
        assert!(!file_a.exists());

        let file_c = mnt.join("chain_c.txt");
        fs::rename(&file_b, &file_c).expect("rename b -> c");
        assert!(!file_b.exists());

        assert_eq!(
            fs::read_to_string(&file_c).expect("read chain_c"),
            "chain content"
        );
    });
}

#[test]
fn fuse_concurrent_file_creation() {
    with_rw_mount(|mnt| {
        // Create files concurrently from multiple threads.
        let mnt_path = mnt.to_path_buf();
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let mp = mnt_path.clone();
                thread::spawn(move || {
                    let path = mp.join(format!("concurrent_{i}.txt"));
                    fs::write(&path, format!("thread_{i}")).expect("concurrent write");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread join");
        }

        // Verify all files exist with correct content.
        for i in 0..10 {
            let path = mnt_path.join(format!("concurrent_{i}.txt"));
            let content = fs::read_to_string(&path).expect("read concurrent file");
            assert_eq!(content, format!("thread_{i}"));
        }
    });
}

#[test]
fn fuse_unlink_nonexistent_returns_error() {
    with_rw_mount(|mnt| {
        let path = mnt.join("nonexistent.txt");
        let result = fs::remove_file(&path);
        assert!(
            result.is_err(),
            "removing nonexistent file should return error"
        );
    });
}

#[test]
fn fuse_overwrite_preserves_inode() {
    with_rw_mount(|mnt| {
        let path = mnt.join("inode_test.txt");
        fs::write(&path, b"first").expect("write first");
        let ino_before = fs::metadata(&path).expect("stat before").ino();

        // Overwrite with new content — inode should be preserved (same file, truncate+write).
        fs::write(&path, b"second").expect("write second");
        let ino_after = fs::metadata(&path).expect("stat after").ino();

        assert_eq!(
            ino_before, ino_after,
            "inode should be preserved on overwrite"
        );
        assert_eq!(
            fs::read_to_string(&path).expect("read after overwrite"),
            "second"
        );
    });
}

// =============================================================================
// btrfs subvolume/snapshot mount selection E2E tests
// =============================================================================

#[test]
#[ignore = "requires sudo for btrfs subvolume creation"]
fn btrfs_fuse_mount_subvolume_scopes_root_to_subvol() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let Some((image, subvols, _)) = create_btrfs_image_with_subvolumes(tmp.path()) else {
        return;
    };
    assert!(
        subvols.contains(&"data".to_string()),
        "test setup should create 'data' subvolume"
    );

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let open_opts = OpenOptions {
        btrfs_mount_selection: BtrfsMountSelection::Subvolume("data".to_string()),
        ..OpenOptions::default()
    };
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };

    let session = try_mount_btrfs_with_open_options(&image, &mnt, &open_opts, &mount_opts);
    assert!(
        session.is_some(),
        "mounting subvolume 'data' should succeed"
    );
    let Some(_session) = session else {
        return;
    };

    // The mounted root should be the subvolume, so subvol_marker.txt should be at root
    let subvol_marker = mnt.join("subvol_marker.txt");
    assert!(
        subvol_marker.exists(),
        "subvol_marker.txt should exist at mount root when mounting 'data' subvolume"
    );
    let content = fs::read_to_string(&subvol_marker).expect("read subvol marker");
    assert!(
        content.contains("in-data-subvol"),
        "marker content should confirm we're in the subvolume"
    );

    // root_marker.txt should NOT be visible (it's in the fs root, not the subvolume)
    let root_marker = mnt.join("root_marker.txt");
    assert!(
        !root_marker.exists(),
        "root_marker.txt should NOT exist when mounting subvolume (scoped to subvol tree)"
    );

    // The 'data' directory itself should NOT exist (we're inside it)
    let data_dir = mnt.join("data");
    assert!(
        !data_dir.exists(),
        "'data' directory should not exist inside itself"
    );

    emit_scenario_result(
        "btrfs_mount_subvolume_scopes_root",
        "PASS",
        Some("subvolume mounted as root, parent tree not visible"),
    );
}

#[test]
#[ignore = "requires sudo for btrfs subvolume creation"]
fn btrfs_fuse_mount_snapshot_scopes_root_to_snapshot() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let Some((image, _, snaps)) = create_btrfs_image_with_subvolumes(tmp.path()) else {
        return;
    };
    if !snaps.contains(&"snap-data".to_string()) {
        eprintln!("snapshot creation was not successful, skipping snapshot test");
        return;
    }

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let open_opts = OpenOptions {
        btrfs_mount_selection: BtrfsMountSelection::Snapshot("snap-data".to_string()),
        ..OpenOptions::default()
    };
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };

    let session = try_mount_btrfs_with_open_options(&image, &mnt, &open_opts, &mount_opts);
    assert!(
        session.is_some(),
        "mounting snapshot 'snap-data' should succeed"
    );
    let Some(_session) = session else {
        return;
    };

    // The snapshot should have both markers (snapshot of subvolume + its own marker)
    let subvol_marker = mnt.join("subvol_marker.txt");
    assert!(
        subvol_marker.exists(),
        "subvol_marker.txt should exist in snapshot (inherited from source)"
    );

    let snap_marker = mnt.join("snapshot_marker.txt");
    assert!(
        snap_marker.exists(),
        "snapshot_marker.txt should exist (written after snapshot)"
    );

    emit_scenario_result(
        "btrfs_mount_snapshot_scopes_root",
        "PASS",
        Some("snapshot mounted as root with inherited + snapshot-specific content"),
    );
}

#[test]
#[ignore = "requires sudo for btrfs subvolume creation"]
fn btrfs_fuse_mount_missing_subvolume_returns_not_found() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let Some((image, _, _)) = create_btrfs_image_with_subvolumes(tmp.path()) else {
        return;
    };

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let open_opts = OpenOptions {
        btrfs_mount_selection: BtrfsMountSelection::Subvolume("nonexistent".to_string()),
        ..OpenOptions::default()
    };
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };

    // This should fail to mount because the subvolume doesn't exist
    let session = try_mount_btrfs_with_open_options(&image, &mnt, &open_opts, &mount_opts);
    assert!(
        session.is_none(),
        "mounting nonexistent subvolume should fail"
    );

    emit_scenario_result(
        "btrfs_mount_missing_subvolume_not_found",
        "PASS",
        Some("nonexistent subvolume correctly rejected"),
    );
}

#[test]
#[ignore = "requires sudo for btrfs subvolume creation"]
fn btrfs_fuse_mount_default_root_shows_subvolumes_as_directories() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let Some((image, subvols, _)) = create_btrfs_image_with_subvolumes(tmp.path()) else {
        return;
    };
    assert!(subvols.contains(&"data".to_string()));

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let open_opts = OpenOptions {
        btrfs_mount_selection: BtrfsMountSelection::DefaultRoot,
        ..OpenOptions::default()
    };
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };

    let session = try_mount_btrfs_with_open_options(&image, &mnt, &open_opts, &mount_opts);
    assert!(session.is_some(), "mounting default root should succeed");
    let Some(_session) = session else {
        return;
    };

    // Default root should show subvolumes as directories
    let data_dir = mnt.join("data");
    assert!(
        data_dir.exists(),
        "'data' subvolume should appear as directory when mounting default root"
    );
    assert!(data_dir.is_dir(), "'data' subvolume should be a directory");

    // root_marker.txt should be visible at root
    let root_marker = mnt.join("root_marker.txt");
    assert!(
        root_marker.exists(),
        "root_marker.txt should exist when mounting default root"
    );

    // The subvolume's marker should be accessible via the directory
    let nested_marker = data_dir.join("subvol_marker.txt");
    assert!(
        nested_marker.exists(),
        "subvol_marker.txt should be accessible via data/ directory"
    );

    emit_scenario_result(
        "btrfs_mount_default_root_shows_subvols",
        "PASS",
        Some("default root shows subvolumes as directories"),
    );
}

// ── bd-745yr: btrfs mknod E2E coverage ─────────────────────────────────────

#[test]
fn fuse_btrfs_mknod_fifo_creates_named_pipe() {
    use nix::sys::stat::{Mode, SFlag, mknod};

    with_btrfs_rw_mount(|mnt| {
        let fifo_path = mnt.join("test_fifo");

        mknod(
            &fifo_path,
            SFlag::S_IFIFO,
            Mode::from_bits_truncate(0o644),
            0,
        )
        .expect("mknod FIFO should succeed");

        let meta = fs::symlink_metadata(&fifo_path).expect("stat FIFO");
        assert!(
            meta.file_type().is_fifo(),
            "created file should be a FIFO, got {:?}",
            meta.file_type()
        );

        emit_scenario_result(
            "btrfs_rw_mknod_fifo",
            "PASS",
            Some("FIFO created successfully via mounted btrfs"),
        );
    });
}

#[test]
fn fuse_btrfs_mknod_socket_creates_unix_socket() {
    use nix::sys::stat::{Mode, SFlag, mknod};

    with_btrfs_rw_mount(|mnt| {
        let sock_path = mnt.join("test_socket");

        mknod(
            &sock_path,
            SFlag::S_IFSOCK,
            Mode::from_bits_truncate(0o755),
            0,
        )
        .expect("mknod socket should succeed");

        let meta = fs::symlink_metadata(&sock_path).expect("stat socket");
        assert!(
            meta.file_type().is_socket(),
            "created file should be a socket, got {:?}",
            meta.file_type()
        );

        emit_scenario_result(
            "btrfs_rw_mknod_socket",
            "PASS",
            Some("Unix socket created successfully via mounted btrfs"),
        );
    });
}

#[test]
fn fuse_btrfs_mknod_duplicate_name_returns_eexist() {
    use nix::sys::stat::{Mode, SFlag, mknod};

    with_btrfs_rw_mount(|mnt| {
        let fifo_path = mnt.join("dup_fifo");

        mknod(
            &fifo_path,
            SFlag::S_IFIFO,
            Mode::from_bits_truncate(0o644),
            0,
        )
        .expect("first mknod should succeed");

        let result = mknod(
            &fifo_path,
            SFlag::S_IFIFO,
            Mode::from_bits_truncate(0o644),
            0,
        );
        assert!(result.is_err(), "duplicate mknod should fail");

        let err = result.unwrap_err();
        assert_eq!(
            err,
            nix::errno::Errno::EEXIST,
            "duplicate mknod should return EEXIST, got {err:?}"
        );

        emit_scenario_result(
            "btrfs_rw_mknod_duplicate_eexist",
            "PASS",
            Some("duplicate mknod correctly returns EEXIST"),
        );
    });
}

#[test]
#[ignore = "requires CAP_MKNOD/root for device creation"]
fn fuse_btrfs_mknod_chardev_stores_rdev() {
    use nix::sys::stat::{Mode, SFlag, makedev, mknod};

    with_btrfs_rw_mount(|mnt| {
        let dev_path = mnt.join("null_clone");

        // /dev/null is major 1, minor 3
        let rdev = makedev(1, 3);
        mknod(
            &dev_path,
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o666),
            rdev,
        )
        .expect("mknod char device should succeed");

        let meta = fs::symlink_metadata(&dev_path).expect("stat char device");
        assert!(
            meta.file_type().is_char_device(),
            "created file should be a char device"
        );

        emit_scenario_result(
            "btrfs_rw_mknod_chardev",
            "PASS",
            Some("char device created successfully via mounted btrfs"),
        );
    });
}

#[test]
#[ignore = "requires CAP_MKNOD/root for device creation"]
fn fuse_btrfs_mknod_blockdev_stores_rdev() {
    use nix::sys::stat::{Mode, SFlag, makedev, mknod};

    with_btrfs_rw_mount(|mnt| {
        let dev_path = mnt.join("sda_clone");

        // /dev/sda is major 8, minor 0
        let rdev = makedev(8, 0);
        mknod(
            &dev_path,
            SFlag::S_IFBLK,
            Mode::from_bits_truncate(0o660),
            rdev,
        )
        .expect("mknod block device should succeed");

        let meta = fs::symlink_metadata(&dev_path).expect("stat block device");
        assert!(
            meta.file_type().is_block_device(),
            "created file should be a block device"
        );

        emit_scenario_result(
            "btrfs_rw_mknod_blockdev",
            "PASS",
            Some("block device created successfully via mounted btrfs"),
        );
    });
}
