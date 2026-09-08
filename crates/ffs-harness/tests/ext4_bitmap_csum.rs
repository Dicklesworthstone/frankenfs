#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_core::{Ext4JournalReplayMode, OpenFs, OpenOptions};
use ffs_types::GroupNumber;
use std::path::{Path, PathBuf};

fn open_ext4_image(image: &Path) -> OpenFs {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        ..OpenOptions::default()
    };
    OpenFs::open_with_options(&cx, image, &opts).expect("open ext4 image")
}

fn mkfs_metadata_csum_ext4(size_mb: u64) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::TempDir::new().expect("tmpdir for ext4 bitmap csum");
    let image = tmp.path().join("bitmap-csum.ext4");
    let file = std::fs::File::create(&image).expect("create ext4 image");
    file.set_len(size_mb * 1024 * 1024)
        .expect("size ext4 image");
    drop(file);

    let mkfs = std::process::Command::new("mkfs.ext4")
        .args([
            "-F",
            "-b",
            "4096",
            "-O",
            "metadata_csum",
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn mkfs.ext4");
    assert!(
        mkfs.status.success(),
        "mkfs.ext4 failed: stdout={} stderr={}",
        String::from_utf8_lossy(&mkfs.stdout),
        String::from_utf8_lossy(&mkfs.stderr)
    );

    (tmp, image)
}

#[test]
fn ext4_block_bitmap_checksum_tamper_detection_conforms() {
    let cx = Cx::for_testing();
    let (_tmp, image_path) = mkfs_metadata_csum_ext4(64);
    let fs = open_ext4_image(&image_path);

    let gd = fs.read_group_desc(&cx, GroupNumber(0)).expect("read gd");
    fs.read_block_bitmap(&cx, GroupNumber(0))
        .expect("uncorrupted block bitmap checksum");
    let bitmap_block = usize::try_from(gd.block_bitmap).expect("bitmap block fits usize");

    let mut data = std::fs::read(&image_path).expect("read ext4 image");
    let offset = bitmap_block * 4096;
    data[offset] ^= 0xFF;
    std::fs::write(&image_path, data).expect("rewrite corrupted ext4 image");

    let fs = open_ext4_image(&image_path);
    let res = fs.read_block_bitmap(&cx, GroupNumber(0));
    assert!(
        res.is_err(),
        "Reading corrupted block bitmap should fail checksum verification"
    );
}

#[test]
fn ext4_inode_bitmap_checksum_tamper_detection_conforms() {
    let cx = Cx::for_testing();
    let (_tmp, image_path) = mkfs_metadata_csum_ext4(64);
    let fs = open_ext4_image(&image_path);
    let gd = fs.read_group_desc(&cx, GroupNumber(0)).expect("read gd");
    fs.read_inode_bitmap(&cx, GroupNumber(0))
        .expect("uncorrupted inode bitmap checksum");
    let bitmap_block = usize::try_from(gd.inode_bitmap).expect("bitmap block fits usize");

    let mut data = std::fs::read(&image_path).expect("read ext4 image");
    data[bitmap_block * 4096] ^= 0xFF;
    std::fs::write(&image_path, data).expect("rewrite corrupted inode bitmap");

    let fs = open_ext4_image(&image_path);
    assert!(
        fs.read_inode_bitmap(&cx, GroupNumber(0)).is_err(),
        "reading corrupted inode bitmap must fail checksum verification"
    );
}
